//! seccomp-BPF filter construction for the agent-sandbox daemon.
//!
//! Provides a `default_syscalls` policy used by the sandbox process and a
//! `build_filter` helper that compiles a syscall allow-list into a seccomp
//! filter loaded via `prctl`.

pub mod bpf;
pub mod policy;
pub use bpf::build_filter;
pub use policy::{default_syscalls, syscalls_without_filesystem};
