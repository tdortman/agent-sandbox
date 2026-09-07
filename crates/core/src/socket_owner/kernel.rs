//! Fresh tuple-filtered BPF file iteration, followed by ordinary owner
//! validation.

use std::{
    io::{self, Read},
    net::IpAddr,
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use aya::{Btf, Ebpf, EbpfLoader, maps::Array, programs::Iter};
use nix::unistd::{SysconfVar, sysconf};

use super::{
    OwnerResolution, OwnerSnapshot, ProcessIdentity, SocketIdentity, SocketInode, SocketProtocol,
    SocketTuple, validate_socket_identity_with_hint,
};

const RECORD_SIZE: usize = 48;
const MAX_OUTPUT: u64 = 1024 * 1024;
static NEXT_QUERY: AtomicU64 = AtomicU64::new(1);

/**
Optional live kernel ownership resolver for trusted daemons in the host PID
namespace. A complete iterator result replaces procfs enumeration; it never
grants policy and every unique result is revalidated through procfs.
*/
#[derive(Debug)]
pub struct KernelOwnerResolver {
    state: Mutex<Ebpf>,
    hints: Option<Mutex<super::hint::HintPrograms>>,
    clock_ticks: u64,
}

impl KernelOwnerResolver {
    /// Load a trusted root-owned BPF object using the running kernel's BTF.
    ///
    /// # Errors
    /// Returns an error for unavailable BPF support, invalid objects or clock
    /// data.
    pub fn open(object: &Path) -> io::Result<Self> {
        let btf = Btf::from_sys_fs().map_err(io::Error::other)?;

        let mut program = EbpfLoader::new()
            .btf(Some(&btf))
            .load_file(object)
            .map_err(io::Error::other)?;

        let iterator: &mut Iter = program
            .program_mut("asbx_owners")
            .ok_or_else(|| invalid("missing ownership iterator"))?
            .try_into()
            .map_err(io::Error::other)?;

        iterator.load("task_file", &btf).map_err(io::Error::other)?;

        Array::<_, [u8; 48]>::try_from(
            program
                .map("queries")
                .ok_or_else(|| invalid("missing ownership query map"))?,
        )
        .map_err(io::Error::other)?;

        let clock_ticks = sysconf(SysconfVar::CLK_TCK)?
            .and_then(|ticks| u64::try_from(ticks).ok())
            .filter(|ticks| *ticks > 0)
            .ok_or_else(|| invalid("missing clock tick frequency"))?;

        Ok(Self {
            state: Mutex::new(program),
            hints: None,
            clock_ticks,
        })
    }

    /// Attach optional ownership observers loaded into fresh, private pins.
    ///
    /// # Errors
    /// Returns an error if the programs cannot attach or their maps are not
    /// fresh.
    pub fn enable_hints(&mut self, pins: &Path) -> io::Result<()> {
        self.hints = Some(Mutex::new(super::hint::HintPrograms::open(pins)?));
        Ok(())
    }

    /// Resolve all current holders of the tuple inside the reader's network
    /// namespace. Each resolver owns its map and serializes its queries.
    ///
    /// # Errors
    /// Incomplete, stale or unsupported results are errors. Callers may run a
    /// fresh procfs resolution on error, but must never accept partial output.
    pub fn resolve(
        &self,
        protocol: SocketProtocol,
        tuple: SocketTuple,
    ) -> io::Result<OwnerResolution<OwnerSnapshot>> {
        if tuple.local_port == 0 {
            return Ok(OwnerResolution::Missing);
        }

        let nonce = NEXT_QUERY.fetch_add(1, Ordering::Relaxed);
        let query = query_bytes(protocol, tuple, nonce)?;

        if let Some(hints) = &self.hints {
            let result = hints
                .lock()
                .map_err(|_| invalid("ownership hint lock poisoned"))?
                .resolve(query);

            if let Ok(Some(mut record)) = result {
                record[40..44].fill(0);
                let mut data = record.to_vec();
                let mut end = [0; RECORD_SIZE];
                end[..8].copy_from_slice(&nonce.to_ne_bytes());
                end[40..44].copy_from_slice(&1u32.to_ne_bytes());
                data.extend_from_slice(&end);

                if let Ok(owner) = Self::parse(&data, nonce, tuple, self.clock_ticks) {
                    tracing::debug!("kernel owner hint completed");
                    return Ok(owner);
                }
            }
        }

        // ponytail: serialize scans; use per-thread resolvers if parallel NFQUEUE
        // queries matter.
        let mut state = self
            .state
            .lock()
            .map_err(|_| invalid("ownership resolver lock poisoned"))?;

        Array::<_, [u8; 48]>::try_from(
            state
                .map_mut("queries")
                .ok_or_else(|| invalid("missing ownership query map"))?,
        )
        .map_err(io::Error::other)?
        .set(0, query, 0)
        .map_err(io::Error::other)?;

        let mut data = Vec::new();

        let iterator: &mut Iter = state
            .program_mut("asbx_owners")
            .ok_or_else(|| invalid("missing ownership iterator"))?
            .try_into()
            .map_err(io::Error::other)?;

        let link = iterator.attach().map_err(io::Error::other)?;

        iterator
            .take_link(link)
            .map_err(io::Error::other)?
            .into_file()
            .map_err(io::Error::other)?
            .take(MAX_OUTPUT + 1)
            .read_to_end(&mut data)?;
        // The query map must stay locked until the iterator finishes reading.
        drop(state);

        if data.len() as u64 > MAX_OUTPUT {
            return Err(invalid("ownership iterator output exceeds limit"));
        }

        Self::parse(&data, nonce, tuple, self.clock_ticks)
    }

    fn parse(
        data: &[u8],
        nonce: u64,
        tuple: SocketTuple,
        clock_ticks: u64,
    ) -> io::Result<OwnerResolution<OwnerSnapshot>> {
        if data.is_empty() || !data.len().is_multiple_of(RECORD_SIZE) {
            return Err(invalid("truncated ownership iterator output"));
        }

        let mut owners = Vec::new();
        let mut incompatible_holder = false;

        for (index, record) in data.as_chunks::<RECORD_SIZE>().0.iter().enumerate() {
            let u64_at = |offset| {
                u64::from_ne_bytes(record[offset..offset + 8].try_into().expect("record field"))
            };

            let u32_at = |offset| {
                u32::from_ne_bytes(record[offset..offset + 4].try_into().expect("record field"))
            };

            if u64_at(0) != nonce {
                return Err(invalid("ownership query changed during iteration"));
            }

            if index == data.len() / RECORD_SIZE - 1 {
                if u32_at(40) != 1
                    || record[8..40]
                        .iter()
                        .chain(&record[44..])
                        .any(|byte| *byte != 0)
                {
                    return Err(invalid("missing ownership completion record"));
                }

                continue;
            }

            if u32_at(40) != 0 || u32_at(44) > 1 {
                return Err(invalid(&format!(
                    "invalid ownership iterator record (status {}, fd {})",
                    u32_at(44),
                    u32_at(36)
                )));
            }

            incompatible_holder |= u32_at(44) != 0;

            let ticks =
                u64::try_from(u128::from(u64_at(16)) * u128::from(clock_ticks) / 1_000_000_000)
                    .map_err(|_| invalid("process start time overflow"))?;

            let identity = ProcessIdentity::new(u32_at(24), u32_at(32), ticks)
                .map_err(|_| invalid("invalid process identity"))?;

            let inode = SocketInode::new(u64_at(8)).map_err(|_| invalid("invalid socket inode"))?;
            let owner = OwnerSnapshot::new(SocketIdentity::new(identity, inode), tuple, u32_at(36));

            if !owners
                .iter()
                .any(|previous: &OwnerSnapshot| previous.identity() == owner.identity())
            {
                owners.push(owner);
            }
        }

        if incompatible_holder || owners.len() > 1 {
            return Ok(OwnerResolution::Ambiguous);
        }

        let Some(owner) = owners.pop() else {
            return Ok(OwnerResolution::Missing);
        };

        if !validate_socket_identity_with_hint(owner.identity(), Some(owner.fd_number())) {
            return Err(invalid("kernel ownership snapshot is no longer valid"));
        }

        Ok(OwnerResolution::Unique(owner))
    }
}

fn query_bytes(protocol: SocketProtocol, tuple: SocketTuple, nonce: u64) -> io::Result<[u8; 48]> {
    if tuple.local_ip.is_ipv4() != tuple.remote_ip.is_ipv4() {
        return Err(invalid("mixed address families"));
    }

    let mut bytes = [0; 48];
    bytes[..8].copy_from_slice(&nonce.to_ne_bytes());

    for (offset, address) in [(8, tuple.local_ip), (24, tuple.remote_ip)] {
        match address {
            IpAddr::V4(address) => bytes[offset..offset + 4].copy_from_slice(&address.octets()),
            IpAddr::V6(address) => bytes[offset..offset + 16].copy_from_slice(&address.octets()),
        }
    }

    bytes[40..42].copy_from_slice(&tuple.local_port.to_ne_bytes());
    bytes[42..44].copy_from_slice(&tuple.remote_port.to_be_bytes());

    bytes[44..46]
        .copy_from_slice(&(if tuple.local_ip.is_ipv4() { 2u16 } else { 10 }).to_ne_bytes());

    bytes[46..48].copy_from_slice(
        &(match protocol {
            SocketProtocol::Tcp => 6u16,
            SocketProtocol::Udp => 17,
        })
        .to_ne_bytes(),
    );

    Ok(bytes)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_or_invalid_scans_cannot_resolve() {
        let tuple = SocketTuple::from_local("127.0.0.1".parse().unwrap(), 1234);
        let mut end = [0u8; RECORD_SIZE];
        end[..8].copy_from_slice(&7u64.to_ne_bytes());
        end[40..44].copy_from_slice(&1u32.to_ne_bytes());

        assert_eq!(
            KernelOwnerResolver::parse(&end, 7, tuple, 100).unwrap(),
            OwnerResolution::Missing
        );

        assert!(KernelOwnerResolver::parse(&[], 7, tuple, 100).is_err());
        assert!(KernelOwnerResolver::parse(&end[..47], 7, tuple, 100).is_err());
        assert!(KernelOwnerResolver::parse(&end, 8, tuple, 100).is_err());
        end[40] = 0;
        assert!(KernelOwnerResolver::parse(&end, 7, tuple, 100).is_err());
        let mut failed = end.to_vec();
        failed[44..48].copy_from_slice(&2u32.to_ne_bytes());
        end[40] = 1;
        failed.extend_from_slice(&end);
        assert!(KernelOwnerResolver::parse(&failed, 7, tuple, 100).is_err());
    }
}
