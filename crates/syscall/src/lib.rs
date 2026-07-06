pub mod bpf;
pub mod policy;

pub use bpf::build_filter;
pub use policy::{default_syscalls, nr};

// Raw seccomp return codes. The BPF builder no longer uses these directly;
// seccompiler owns the return code generation. They are kept here for
// callers (and tests) that need to interpret raw return codes from
// notifications or trace events.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;

// Flags and operation codes for the seccomp syscall. The arm main.rs uses
// these when installing the filter via `SYS_seccomp`.
pub const LISTENER_FLAG_NEW_LISTENER: u16 = 8;
pub const SECCOMP_SET_MODE_FILTER: u32 = 1;
