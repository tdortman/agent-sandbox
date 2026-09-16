//! Pinned verdict map shared by the NFQUEUE daemon and the in-kernel gate.
//!
//! The NFQUEUE daemon owns every write: it already holds the policyd
//! connection, it runs inside the sandbox network namespace, and it can read
//! that namespace's cookie with `SO_NETNS_COOKIE`. The `cgroup/connect4` and
//! `cgroup/connect6` programs in
//! `nix/modules/nixos/agent-sandbox/policy/gate.bpf.c` read the same entries
//! and fail a denied connection before any packet exists.
//!
//! Every identity here is the network namespace cookie, the same key the
//! loopback bridge uses (`loopback/redirect.bpf.c`), so one sandbox can never
//! read or write another's entries. A stale entry is inert: the kernel
//! program compares the entry generation against the namespace generation and
//! treats a mismatch as a miss, which sends the flow back down the ordinary
//! userspace policy path.
//!
//! Encoding is explicit and native-endian, matching the C structs the kernel
//! program builds on the stack.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsFd,
    path::Path,
};

use agent_sandbox_sysutil as sysutil;
use aya::maps::{MapData, MapType};

/// Protocol identifier stored in a [`DestKey`], matching `IPPROTO_TCP`.
pub const VERDICT_PROTO_TCP: u8 = 6;

/// Protocol identifier stored in a [`DestKey`], matching `IPPROTO_UDP`.
pub const VERDICT_PROTO_UDP: u8 = 17;

/// Verdict value refusing the flow.
pub const VERDICT_DENY: u8 = 0;

/// Verdict value permitting the flow.
pub const VERDICT_ALLOW: u8 = 1;

/// Name of the pinned destination verdict map.
pub const VERDICT_MAP_NAME: &str = "verdicts";

/// Name of the pinned per-namespace state map.
pub const STATE_MAP_NAME: &str = "namespace_state";

/// Encoded size of [`DestKey`], matching `sizeof(struct dest_key)`.
pub const DEST_KEY_SIZE: usize = 32;

/// Encoded size of [`VerdictValue`], matching `sizeof(struct verdict_value)`.
pub const VERDICT_VALUE_SIZE: usize = 8;

/// Encoded size of [`NamespaceState`], matching `sizeof(struct
/// namespace_state)`.
pub const NAMESPACE_STATE_SIZE: usize = 16;

/// One destination in one sandbox network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestKey {
    /// Network namespace cookie of the sandbox the flow belongs to.
    pub netns_cookie: u64,
    /// [`VERDICT_PROTO_TCP`] or [`VERDICT_PROTO_UDP`].
    pub proto: u8,
    /// Destination address in the 16-byte field, IPv4 stored v4-mapped.
    pub ip: [u8; 16],
    /// Destination port in network byte order, as the packet headers and the
    /// kernel context carry it.
    pub port: u16,
}

impl DestKey {
    /// Build a key for one destination in one sandbox namespace.
    ///
    /// IPv4 is stored in the v4-mapped IPv6 form so the kernel program and
    /// userspace share one encoding without a family field in the key.
    #[must_use]
    pub fn new(netns_cookie: u64, proto: u8, ip: IpAddr, port: u16) -> Self {
        let mut bytes = [0_u8; 16];
        match ip {
            IpAddr::V4(v4) => {
                bytes[10] = 0xFF;
                bytes[11] = 0xFF;
                bytes[12..].copy_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => bytes.copy_from_slice(&v6.octets()),
        }

        Self {
            netns_cookie,
            proto,
            ip: bytes,
            port: port.to_be(),
        }
    }

    /// Address the key refers to, decoding the v4-mapped form as IPv4.
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        if self.ip[..10].iter().all(|byte| *byte == 0) && self.ip[10] == 0xFF && self.ip[11] == 0xFF
        {
            return IpAddr::V4(Ipv4Addr::new(
                self.ip[12],
                self.ip[13],
                self.ip[14],
                self.ip[15],
            ));
        }

        IpAddr::V6(Ipv6Addr::from(self.ip))
    }

    /// Destination port in host byte order.
    #[must_use]
    pub const fn port(&self) -> u16 {
        u16::from_be(self.port)
    }

    /// Encode the key exactly as `struct dest_key` lays it out.
    #[must_use]
    pub fn encode(&self) -> [u8; DEST_KEY_SIZE] {
        let mut bytes = [0_u8; DEST_KEY_SIZE];
        bytes[..8].copy_from_slice(&self.netns_cookie.to_ne_bytes());
        bytes[8] = self.proto;
        bytes[12..28].copy_from_slice(&self.ip);
        bytes[28..30].copy_from_slice(&self.port.to_ne_bytes());
        bytes
    }
}

/// One cached destination verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictValue {
    /// [`VERDICT_ALLOW`] or [`VERDICT_DENY`].
    pub verdict: u8,
    /// Namespace generation this entry was published under.
    pub generation: u32,
}

impl VerdictValue {
    /// Encode the value exactly as `struct verdict_value` lays it out.
    #[must_use]
    pub fn encode(&self) -> [u8; VERDICT_VALUE_SIZE] {
        let mut bytes = [0_u8; VERDICT_VALUE_SIZE];
        bytes[0] = self.verdict;
        bytes[4..8].copy_from_slice(&self.generation.to_ne_bytes());
        bytes
    }

    /// Decode a value the kernel filled.
    #[must_use]
    pub const fn decode(bytes: &[u8; VERDICT_VALUE_SIZE]) -> Self {
        let generation = u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        Self {
            verdict: bytes[0],
            generation,
        }
    }
}

/// Decision-set state for one sandbox network namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceState {
    /// Generation of the current decision set. Entries from an older
    /// generation are ignored, which is how a wholesale invalidation avoids
    /// walking the verdict map.
    pub generation: u32,
    /// Non-zero while this namespace must not open new flows.
    pub blocked: u32,
    /// UID of the trusted proxy. The proxy connects from inside the same
    /// namespace, so its own upstream sockets are exempt.
    pub proxy_uid: u32,
    /// Reserved for future gate flags.
    pub reserved: u32,
}

impl NamespaceState {
    /// A state that permits flows, at the given generation.
    #[must_use]
    pub const fn open(generation: u32, proxy_uid: u32) -> Self {
        Self {
            generation,
            blocked: 0,
            proxy_uid,
            reserved: 0,
        }
    }

    /// Whether the kernel must refuse new flows for this namespace.
    #[must_use]
    pub const fn blocks_flows(&self) -> bool {
        self.blocked != 0
    }

    /// Encode the state exactly as `struct namespace_state` lays it out.
    #[must_use]
    pub fn encode(&self) -> [u8; NAMESPACE_STATE_SIZE] {
        let mut bytes = [0_u8; NAMESPACE_STATE_SIZE];
        bytes[..4].copy_from_slice(&self.generation.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.blocked.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.proxy_uid.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.reserved.to_ne_bytes());
        bytes
    }

    /// Decode a state the kernel filled.
    #[must_use]
    pub const fn decode(bytes: &[u8; NAMESPACE_STATE_SIZE]) -> Self {
        Self {
            generation: u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            blocked: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            proxy_uid: u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            reserved: u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        }
    }
}

/// An opened pair of pinned maps.
#[derive(Debug)]
pub struct VerdictMap {
    verdicts: MapData,
    states: MapData,
    generation: u32,
}

impl VerdictMap {
    /// Open the pinned maps from the directory the Nix module pins them in.
    ///
    /// # Errors
    /// Returns an error for missing pins or an incompatible map layout.
    pub fn open(directory: &Path) -> io::Result<Self> {
        let verdicts = open_map(
            &directory.join(VERDICT_MAP_NAME),
            MapType::LruHash,
            DEST_KEY_SIZE,
            VERDICT_VALUE_SIZE,
        )?;
        let states = open_map(
            &directory.join(STATE_MAP_NAME),
            MapType::Hash,
            std::mem::size_of::<u64>(),
            NAMESPACE_STATE_SIZE,
        )?;

        Ok(Self {
            verdicts,
            states,
            generation: 0,
        })
    }

    /// Generation the next published entry carries.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Read the state of one sandbox namespace.
    ///
    /// # Errors
    /// Returns an error when the map cannot be read.
    pub fn state(&self, netns_cookie: u64) -> io::Result<Option<NamespaceState>> {
        let mut value = [0_u8; NAMESPACE_STATE_SIZE];
        let found = sysutil::bpf_map_lookup(
            self.states.fd().as_fd(),
            &netns_cookie.to_ne_bytes(),
            &mut value,
        )?;

        Ok(found.then(|| NamespaceState::decode(&value)))
    }

    /// Publish the state of one sandbox namespace.
    ///
    /// # Errors
    /// Returns an error when the map cannot be written.
    pub fn set_state(&mut self, netns_cookie: u64, state: NamespaceState) -> io::Result<()> {
        self.generation = state.generation;
        sysutil::bpf_map_update(
            self.states.fd().as_fd(),
            &netns_cookie.to_ne_bytes(),
            &state.encode(),
            0,
        )
    }

    /// Block new flows for one namespace while a decision change is applied.
    ///
    /// # Errors
    /// Returns an error when the map cannot be written.
    pub fn set_blocked(&mut self, netns_cookie: u64, blocked: bool) -> io::Result<()> {
        let mut state = self
            .state(netns_cookie)?
            .unwrap_or_else(|| NamespaceState::open(self.generation.max(1), 0));
        state.blocked = u32::from(blocked);
        self.set_state(netns_cookie, state)
    }

    /// Invalidate every published verdict for one namespace.
    ///
    /// Old entries stay in the map carrying a generation the kernel program
    /// rejects, so a wholesale invalidation costs one write instead of a scan.
    ///
    /// # Errors
    /// Returns an error when the map cannot be written.
    pub fn invalidate(&mut self, netns_cookie: u64) -> io::Result<u32> {
        let mut state = self
            .state(netns_cookie)?
            .unwrap_or_else(|| NamespaceState::open(self.generation.max(1), 0));
        state.generation = state.generation.wrapping_add(1);
        self.set_state(netns_cookie, state)?;
        Ok(state.generation)
    }

    /// Publish one destination verdict under the current generation.
    ///
    /// # Errors
    /// Returns an error when the map cannot be written.
    pub fn publish(&self, key: &DestKey, verdict: u8) -> io::Result<()> {
        let value = VerdictValue {
            verdict,
            generation: self.generation,
        };
        sysutil::bpf_map_update(
            self.verdicts.fd().as_fd(),
            &key.encode(),
            &value.encode(),
            0,
        )
    }

    /// Read one destination verdict.
    ///
    /// # Errors
    /// Returns an error when the map cannot be read.
    pub fn lookup(&self, key: &DestKey) -> io::Result<Option<VerdictValue>> {
        let mut value = [0_u8; VERDICT_VALUE_SIZE];
        let found = sysutil::bpf_map_lookup(self.verdicts.fd().as_fd(), &key.encode(), &mut value)?;

        Ok(found.then(|| VerdictValue::decode(&value)))
    }

    /// Drop one destination verdict.
    ///
    /// # Errors
    /// Returns an error when the map cannot be written.
    pub fn remove(&self, key: &DestKey) -> io::Result<()> {
        sysutil::bpf_map_delete(self.verdicts.fd().as_fd(), &key.encode())
    }
}

/// Open one pinned map after checking that its type and layout match.
fn open_map(
    path: &Path,
    map_type: MapType,
    key_size: usize,
    value_size: usize,
) -> io::Result<MapData> {
    let data = MapData::from_pin(path).map_err(io::Error::other)?;
    let info = data.info().map_err(io::Error::other)?;
    if info.map_type().map_err(io::Error::other)? != map_type
        || info.key_size() as usize != key_size
        || info.value_size() as usize != value_size
    {
        return Err(io::Error::other("invalid verdict map layout"));
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(cookie: u64, address: [u8; 4], port: u16) -> DestKey {
        DestKey::new(
            cookie,
            VERDICT_PROTO_TCP,
            IpAddr::V4(Ipv4Addr::from(address)),
            port,
        )
    }

    #[test]
    fn a_v4_key_encodes_the_kernel_layout() {
        let key = v4(7, [93, 184, 216, 34], 443);
        let bytes = key.encode();

        assert_eq!(bytes.len(), DEST_KEY_SIZE);
        assert_eq!(bytes[..8], 7_u64.to_ne_bytes());
        assert_eq!(bytes[8], VERDICT_PROTO_TCP);
        assert_eq!(bytes[12..28], [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 93, 184, 216, 34
        ]);
        assert_eq!(bytes[28..30], 443_u16.to_be().to_ne_bytes());
        assert_eq!(key.ip(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(key.port(), 443);
    }

    #[test]
    fn a_v6_key_round_trips_through_the_encoding() {
        let address: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().expect("valid");
        let key = DestKey::new(9, VERDICT_PROTO_UDP, address, 443);
        let bytes = key.encode();

        assert_eq!(bytes[8], VERDICT_PROTO_UDP);
        assert_eq!(key.ip(), address);
        assert_eq!(key.port(), 443);
    }

    #[test]
    fn a_v6_address_with_a_leading_zero_run_stays_ipv6() {
        let address: IpAddr = "::1:0:1".parse().expect("valid");
        let key = DestKey::new(1, VERDICT_PROTO_TCP, address, 80);

        assert_eq!(key.ip(), address);
    }

    #[test]
    fn only_the_v4_mapped_prefix_decodes_as_ipv4() {
        let almost_mapped: IpAddr = "::ff:0:0:0:0".parse().expect("valid");
        let key = DestKey::new(1, VERDICT_PROTO_TCP, almost_mapped, 80);

        assert_eq!(key.ip(), almost_mapped);
    }

    #[test]
    fn verdict_values_round_trip() {
        let value = VerdictValue {
            verdict: VERDICT_ALLOW,
            generation: 42,
        };
        let decoded = VerdictValue::decode(&value.encode());

        assert_eq!(decoded, value);
    }

    #[test]
    fn namespace_states_round_trip_and_report_blocking() {
        let state = NamespaceState::open(3, 976);
        assert!(!state.blocks_flows());
        assert_eq!(NamespaceState::decode(&state.encode()), state);

        let blocked = NamespaceState {
            blocked: 1,
            ..state
        };
        assert!(blocked.blocks_flows());
    }
}
