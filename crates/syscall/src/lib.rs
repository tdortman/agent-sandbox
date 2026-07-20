pub mod bpf;
pub mod policy;

pub use bpf::build_filter;
pub use policy::{default_syscalls, nr};

// Raw seccomp return codes used by the BPF filter tests.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const RET_ALLOW: u32 = 0x7fff_0000;
