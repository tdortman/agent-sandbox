//! FUSE mounts inside agent sandboxes.
//!
//! A sandbox cannot run a setuid `fusermount3`, so the sandbox carries a shim
//! ([`fusermount`], [`shim`]) that asks policyd to mount. policyd runs the
//! root helper ([`helper`]), which enters the sandbox's mount namespace,
//! checks the request ([`options`], [`mountpoint`]) and mounts with the new
//! mount API ([`kernel`]). The helper reports back over [`protocol`].

pub mod fusermount;
pub mod helper;
pub mod kernel;
pub mod mountpoint;
pub mod options;
pub mod protocol;
pub mod shim;
