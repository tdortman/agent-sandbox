//! Tracee syscall arguments, captured once per notification.
//!
//! Every pointer argument a decision depends on (pathname, `open_how`,
//! sockaddr, `msghdr`) is read here exactly once. Classification, policy
//! dispatch and emulation all consume the captured value, so a tracee thread
//! racing the notification cannot make them disagree.

use std::io;

use agent_sandbox_syscall::policy::nr;
use agent_sandbox_sysutil::{read_tracee_bytes, read_tracee_path_with};

use crate::SeccompNotif;

/// Largest sockaddr prefix captured; `sockaddr_un` is 110 bytes.
const SOCKADDR_CAPTURE: usize = 128;

/// Messages of a `sendmmsg` batch inspected for their destinations.
const BATCH_LIMIT: usize = 1024;

/// Size of the `struct msghdr` prefix captured.
const MSGHDR_LEN: usize = 56;

/// Size of one `struct mmsghdr` array element.
const MMSGHDR_LEN: usize = 64;

#[cfg(target_pointer_width = "64")]
const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(offset_of!(libc::msghdr, msg_name) == 0);
    assert!(offset_of!(libc::msghdr, msg_namelen) == 8);
    assert!(offset_of!(libc::msghdr, msg_iov) == 16);
    assert!(offset_of!(libc::msghdr, msg_iovlen) == 24);
    assert!(offset_of!(libc::msghdr, msg_control) == 32);
    assert!(offset_of!(libc::msghdr, msg_controllen) == 40);
    assert!(size_of::<libc::msghdr>() == MSGHDR_LEN);
    assert!(size_of::<libc::mmsghdr>() == MMSGHDR_LEN);
};

/// Decode an `int` syscall argument from the register's low 32 bits.
pub const fn syscall_i32_arg(arg: u64) -> i32 {
    let bytes = arg.to_le_bytes();
    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// The `dirfd` argument value that means "the working directory".
pub fn at_fdcwd_arg() -> u64 {
    i64::from(libc::AT_FDCWD).cast_unsigned()
}

fn efault() -> io::Error {
    io::Error::from_raw_os_error(libc::EFAULT)
}

fn word(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn half_word(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// `struct open_how` as the tracee passed it, or its register equivalent for
/// `open`, `openat` and `creat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenHow {
    pub flags: i32,
    pub mode: u32,
    pub resolve: u64,
}

impl OpenHow {
    /// Size of `struct open_how` (`OPEN_HOW_SIZE_VER0`).
    const LEN: usize = 24;

    fn parse(bytes: &[u8]) -> io::Result<Self> {
        let invalid = || io::Error::from_raw_os_error(libc::EINVAL);
        let (Some(flags), Some(mode), Some(resolve)) =
            (word(bytes, 0), word(bytes, 8), word(bytes, 16))
        else {
            return Err(efault());
        };

        Ok(Self {
            flags: i32::try_from(flags).map_err(|_| invalid())?,
            mode: u32::try_from(mode).map_err(|_| invalid())?,
            resolve,
        })
    }
}

/// Where the open flags of a notified open-family syscall live.
#[derive(Debug, Clone, Copy)]
enum HowSource {
    Registers(OpenHow),
    Pointer(u64),
}

/// The register-resident arguments of an `open`, `openat`, `openat2` or
/// `creat` notification.
#[derive(Debug, Clone, Copy)]
pub struct OpenArgs {
    path_ptr: u64,
    dirfd: u64,
    how: HowSource,
}

/// An open-family syscall's pointer arguments, read once.
#[derive(Debug)]
pub struct OpenCapture {
    /// Pathname without its terminator.
    pub path: Vec<u8>,

    /// Raw `dirfd` argument; `AT_FDCWD` for `open` and `creat`.
    pub dirfd: u64,

    /// Flags, mode and resolve flags the open requested.
    pub how: OpenHow,
}

impl OpenArgs {
    /// Decode an open-family notification; `None` for other syscalls.
    pub fn from_notification(notif: &SeccompNotif) -> Option<Self> {
        let args = &notif.data.args;
        let registers = |path_ptr, dirfd, flags, mode| Self {
            path_ptr,
            dirfd,
            how: HowSource::Registers(OpenHow {
                flags: syscall_i32_arg(flags),
                mode: syscall_i32_arg(mode).cast_unsigned(),
                resolve: 0,
            }),
        };

        match i64::from(notif.data.nr) {
            nr::OPEN => Some(registers(args[0], at_fdcwd_arg(), args[1], args[2])),
            nr::OPENAT => Some(registers(args[1], args[0], args[2], args[3])),

            // creat() takes no flags and truncates an existing path.
            nr::CREAT => Some(registers(
                args[0],
                at_fdcwd_arg(),
                (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)
                    .cast_unsigned()
                    .into(),
                args[1],
            )),

            // openat2's flags live behind a pointer, so proving a device
            // cannot be reached would cost the read it is meant to avoid.
            nr::OPENAT2 => Some(Self {
                path_ptr: args[1],
                dirfd: args[0],
                how: HowSource::Pointer(args[2]),
            }),

            _ => None,
        }
    }

    /// Whether the register flags prove the syscall cannot reach an existing
    /// device node, which is the only target class the resource gate covers.
    ///
    /// `O_DIRECTORY` only opens a directory, and `O_CREAT|O_EXCL` fails with
    /// `EEXIST` on anything that exists, including a device node and a
    /// symlink. Skipping classification for those saves the tracee memory read
    /// and the type `stat` that every other open pays.
    pub const fn proves_not_a_device(&self) -> bool {
        let HowSource::Registers(how) = self.how else {
            return false;
        };

        how.flags & libc::O_DIRECTORY != 0
            || (how.flags & libc::O_CREAT != 0 && how.flags & libc::O_EXCL != 0)
    }

    /// Read the pathname and, for `openat2`, the `open_how` behind its
    /// pointer. `None` for a null pathname.
    ///
    /// # Errors
    /// Returns the tracee read error, `ENAMETOOLONG` for an unterminated
    /// pathname, or `EINVAL` for flags outside `int`.
    pub fn capture(&self, pid: u32) -> io::Result<Option<OpenCapture>> {
        self.capture_with(|addr, len| read_tracee_bytes(pid, addr, len))
    }

    /// [`Self::capture`] over an explicit tracee memory reader.
    pub fn capture_with<R>(&self, mut read: R) -> io::Result<Option<OpenCapture>>
    where
        R: FnMut(u64, usize) -> io::Result<Vec<u8>>,
    {
        if self.path_ptr == 0 {
            return Ok(None);
        }

        let path = read_tracee_path_with(&mut read, self.path_ptr)?;

        let how = match self.how {
            HowSource::Registers(how) => how,
            HowSource::Pointer(0) => return Err(efault()),
            HowSource::Pointer(ptr) => OpenHow::parse(&read(ptr, OpenHow::LEN)?)?,
        };

        Ok(Some(OpenCapture {
            path,
            dirfd: self.dirfd,
            how,
        }))
    }
}

/// A sockaddr captured from the tracee.
#[derive(Debug)]
pub struct Sockaddr {
    /// Bytes read, at most [`SOCKADDR_CAPTURE`].
    pub bytes: Vec<u8>,

    /// Length the tracee claimed.
    pub len: usize,
}

/// Read the sockaddr at `addr`. `None` for a null pointer or zero length.
///
/// # Errors
/// Returns the tracee read error.
pub fn read_sockaddr(pid: u32, addr: u64, len: u64) -> io::Result<Option<Sockaddr>> {
    let len = usize::try_from(len).unwrap_or(0);

    if addr == 0 || len == 0 {
        return Ok(None);
    }

    Ok(Some(Sockaddr {
        bytes: read_tracee_bytes(pid, addr, len.min(SOCKADDR_CAPTURE))?,
        len,
    }))
}

/// The `struct msghdr` fields the broker uses, copied from the tracee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msghdr {
    /// `msg_name`: destination sockaddr pointer.
    pub name: u64,

    /// `msg_namelen`.
    pub name_len: u32,

    /// `msg_iov`: payload vector pointer.
    pub iov: u64,

    /// `msg_iovlen`.
    pub iov_len: u64,

    /// `msg_control`: ancillary data pointer.
    pub control: u64,

    /// `msg_controllen`.
    pub control_len: u64,
}

impl Msghdr {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        let fields = (|| {
            Some(Self {
                name: word(bytes, 0)?,
                name_len: half_word(bytes, 8)?,
                iov: word(bytes, 16)?,
                iov_len: word(bytes, 24)?,
                control: word(bytes, 32)?,
                control_len: word(bytes, 40)?,
            })
        })();

        fields.ok_or_else(efault)
    }

    /// Whether the message carries ancillary data (`SCM_RIGHTS` and friends).
    #[must_use]
    pub const fn has_control(&self) -> bool {
        self.control != 0 && self.control_len != 0
    }
}

/// A message's destination: its header and the sockaddr it names.
#[derive(Debug)]
pub struct Destination {
    pub msghdr: Msghdr,
    pub sockaddr: Sockaddr,
}

fn read_destination(pid: u32, msghdr: Msghdr) -> io::Result<Option<Destination>> {
    Ok(read_sockaddr(pid, msghdr.name, u64::from(msghdr.name_len))?
        .map(|sockaddr| Destination { msghdr, sockaddr }))
}

/// Capture a `sendmsg` message header and the destination it names. `None`
/// when the message names none.
///
/// # Errors
/// Returns the tracee read error, or `EFAULT` for a header cut short.
pub fn capture_sendmsg(pid: u32, msg: u64) -> io::Result<Option<Destination>> {
    if msg == 0 {
        return Ok(None);
    }

    let msghdr = Msghdr::parse(&read_tracee_bytes(pid, msg, MSGHDR_LEN)?)?;
    read_destination(pid, msghdr)
}

/// The destinations of a `sendmmsg` batch.
#[derive(Debug)]
pub enum Batch {
    /// No message names a destination.
    Unaddressed,

    /// Every addressed message names this destination (the first one).
    Single(Destination),

    /// Messages name different destinations.
    Conflicting,
}

/// Capture every message header of a `sendmmsg` batch, and each destination it
/// names, once.
///
/// # Errors
/// Returns the tracee read error, or `EFAULT` for a header cut short.
pub fn capture_sendmmsg(pid: u32, msgvec: u64, vlen: usize) -> io::Result<Batch> {
    let mut first: Option<Destination> = None;

    for index in 0..vlen.min(BATCH_LIMIT) {
        let offset = msgvec.saturating_add(u64::try_from(index * MMSGHDR_LEN).unwrap_or(u64::MAX));
        let entry = read_tracee_bytes(pid, offset, MMSGHDR_LEN)?;
        let Some(destination) = read_destination(pid, Msghdr::parse(&entry)?)? else {
            continue;
        };

        match &first {
            None => first = Some(destination),
            Some(first) if first.sockaddr.bytes != destination.sockaddr.bytes => {
                return Ok(Batch::Conflicting);
            }
            Some(_) => {}
        }
    }

    Ok(first.map_or(Batch::Unaddressed, Batch::Single))
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, io};

    use agent_sandbox_syscall::policy::nr;

    use super::{OpenArgs, OpenHow, at_fdcwd_arg, syscall_i32_arg};
    use crate::{SeccompData, SeccompNotif};

    fn notif(syscall: i64, args: [u64; 6]) -> SeccompNotif {
        SeccompNotif {
            data: SeccompData {
                nr: i32::try_from(syscall).expect("syscall number"),
                args,
                ..SeccompData::default()
            },
            ..SeccompNotif::default()
        }
    }

    fn how_bytes(flags: i32, resolve: u64) -> Vec<u8> {
        let mut bytes = u64::try_from(flags).expect("flags").to_ne_bytes().to_vec();
        bytes.extend_from_slice(&0_u64.to_ne_bytes());
        bytes.extend_from_slice(&resolve.to_ne_bytes());
        bytes
    }

    #[test]
    fn openat2_captures_open_how_once_from_a_single_snapshot() {
        let args = OpenArgs::from_notification(&notif(nr::OPENAT2, [
            at_fdcwd_arg(),
            0x1000,
            0x2000,
            24,
            0,
            0,
        ]))
        .expect("open-family notification");

        // A racing tracee thread rewrites `open_how` after every read.
        let how_reads = Cell::new(0_u32);
        let capture = args
            .capture_with(|addr, len| match addr {
                0x1000 => Ok(b"/dev/kvm\0".to_vec()),
                0x2000 => {
                    let generation = how_reads.get();
                    how_reads.set(generation + 1);
                    assert_eq!(len, 24);

                    Ok(if generation == 0 {
                        how_bytes(libc::O_RDWR, 0x10)
                    } else {
                        how_bytes(libc::O_RDONLY, 0)
                    })
                }
                _ => Err(io::Error::from_raw_os_error(libc::EFAULT)),
            })
            .expect("capture")
            .expect("non-null path");

        assert_eq!(how_reads.get(), 1, "open_how is read exactly once");
        assert_eq!(capture.path, b"/dev/kvm");
        assert_eq!(
            capture.how,
            OpenHow {
                flags: libc::O_RDWR,
                mode: 0,
                resolve: 0x10,
            },
            "flags and resolve come from the same snapshot"
        );
    }

    #[test]
    fn register_flags_decode_from_the_low_word() {
        // Garbage in the upper half of the register must not change the flags.
        let garbage = 0xDEAD_BEEF_0000_0000_u64;
        let args = OpenArgs::from_notification(&notif(nr::OPENAT, [
            at_fdcwd_arg(),
            0x1000,
            garbage | u64::from((libc::O_WRONLY | libc::O_CREAT).cast_unsigned()),
            garbage | 0o600,
            0,
            0,
        ]))
        .expect("open-family notification");
        let capture = args
            .capture_with(|_, _| Ok(b"/dev/kvm\0".to_vec()))
            .expect("capture")
            .expect("non-null path");

        assert_eq!(capture.how.flags, libc::O_WRONLY | libc::O_CREAT);
        assert_eq!(capture.how.mode, 0o600);
    }

    #[test]
    fn open_flags_that_cannot_reach_a_device_skip_classification() {
        let openat = |flags: i32| {
            OpenArgs::from_notification(&notif(nr::OPENAT, [
                at_fdcwd_arg(),
                0,
                u64::from(flags.cast_unsigned()),
                0,
                0,
                0,
            ]))
            .expect("open-family notification")
        };

        assert!(openat(libc::O_RDONLY | libc::O_DIRECTORY).proves_not_a_device());
        assert!(openat(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL).proves_not_a_device());
        assert!(openat(libc::O_TMPFILE | libc::O_RDWR).proves_not_a_device());

        // A create that may open an existing path, and a plain open, are
        // classified normally.
        assert!(!openat(libc::O_WRONLY | libc::O_CREAT).proves_not_a_device());
        assert!(!openat(libc::O_RDWR).proves_not_a_device());

        let creat =
            OpenArgs::from_notification(&notif(nr::CREAT, [0, 0o644, 0, 0, 0, 0])).expect("creat");
        assert!(!creat.proves_not_a_device());
        let openat2 = OpenArgs::from_notification(&notif(nr::OPENAT2, [0, 0, 0x2000, 24, 0, 0]))
            .expect("openat2");
        assert!(!openat2.proves_not_a_device());
    }

    #[test]
    fn syscall_int_arguments_ignore_the_upper_register_half() {
        assert_eq!(syscall_i32_arg(0x1234_5678_FFFF_FF9C), libc::AT_FDCWD);
    }
}
