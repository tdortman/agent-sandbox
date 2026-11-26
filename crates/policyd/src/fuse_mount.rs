//! FUSE mounts in a sandbox's mount namespace.
//!
//! policyd cannot enter a mount namespace itself: `setns(CLONE_NEWNS)` refuses
//! a multithreaded caller. It starts `agent-sandbox-fuse-mount` as root per
//! request instead, handing it the requester as a pidfd and a socket for the
//! reply. After a mount the helper returns the `/dev/fuse` descriptor, which
//! policyd passes on to the requester ahead of its reply line.

use std::{
    ffi::OsString,
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::UnixStream as StdUnixStream,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::{FileAccess, ResolvedRequestContext};
use agent_sandbox_fuse::{
    helper::Action,
    mountpoint::{RefusedPaths, require_clean},
    protocol::{HelperReply, read_reply},
};
use agent_sandbox_sysutil::send_fd;
use nix::sys::socket::{getsockopt, sockopt::PeerPidfd};
use tokio::{io::Interest, net::UnixStream};

use crate::{
    error::PolicydError,
    server::peer::ClientPeer,
    store::{PolicyStore, UiClientHandle},
};

/// How long a helper may take before it is killed.
const HELPER_TIMEOUT: Duration = Duration::from_secs(20);

/// Carry out a mount or unmount for a sandbox process.
///
/// # Errors
/// [`PolicydError::FuseDisabled`] without a configured helper,
/// [`PolicydError::FuseUnverified`] for a requester that is not a verified
/// sandbox process, and [`PolicydError::FuseRefused`] with the helper's reason
/// when it refuses.
pub async fn handle(
    store: &Arc<PolicyStore>,
    client: &UiClientHandle,
    peer: ClientPeer,
    ctx: ResolvedRequestContext,
    mountpoint: PathBuf,
    action: Action,
) -> Result<(), PolicydError> {
    let args = store.args();

    let Some(helper) = args.fuse_mount_cmd.clone() else {
        return Err(PolicydError::FuseDisabled);
    };

    let gid = u32::try_from(peer.gid).map_err(|_| PolicydError::FuseUnverified)?;

    if peer.uid == 0 || ctx.sandbox_session_id.is_none() {
        return Err(PolicydError::FuseUnverified);
    }

    require_clean(&mountpoint).map_err(|err| PolicydError::FuseRefused(err.to_string()))?;

    // The shared policy directory is refused here as well as by the helper, so
    // it never reaches a filesystem approval prompt.
    let shared_dir = args.sandbox_socket.parent().map(Path::to_path_buf);

    if let Some(refused) = RefusedPaths::new(shared_dir.clone()).covering(&mountpoint) {
        return Err(PolicydError::FuseRefused(format!(
            "refusing to mount at or under {}",
            refused.display()
        )));
    }

    // Without the filesystem gate there is no filesystem policy to consult.
    if matches!(action, Action::Mount { .. }) && args.fs_monitor_cmd.is_some() {
        let verdict = store
            .check_filesystem(mountpoint.clone(), FileAccess::Write, ctx)
            .await;

        if !verdict.verdict.allowed {
            return Err(PolicydError::FuseRefused(format!(
                "filesystem policy does not allow writing {}",
                mountpoint.display()
            )));
        }
    }

    // The pidfd names the connecting process for good: a pid that exits and
    // is reused cannot send the helper into another namespace.
    let pidfd = {
        let writer = client.writer.lock().await;
        let stream: &UnixStream = writer.as_ref();
        let pidfd = getsockopt(stream, PeerPidfd);

        drop(writer);
        pidfd.map_err(io::Error::from)?
    };

    let helper_args = helper_args(&action, peer.uid, gid, &mountpoint, shared_dir.as_deref());

    let reply = tokio::task::spawn_blocking(move || {
        run_helper(&helper, &helper_args, pidfd, HELPER_TIMEOUT)
    })
    .await
    .map_err(io::Error::other)??;

    match reply {
        HelperReply::Mounted(fuse_fd) => send_descriptor(client, &fuse_fd).await?,
        HelperReply::Unmounted => {}
        HelperReply::Refused(reason) => return Err(PolicydError::FuseRefused(reason)),
    }

    Ok(())
}

fn helper_args(
    action: &Action,
    uid: u32,
    gid: u32,
    mountpoint: &Path,
    shared_dir: Option<&Path>,
) -> Vec<OsString> {
    // `--name=value` keeps a value that starts with `-` from reading as a flag.
    let mut args: Vec<OsString> = match action {
        Action::Mount { options } => {
            vec!["mount".into(), format!("--options={options}").into()]
        }
        Action::Unmount { lazy } => std::iter::once("unmount")
            .chain(lazy.then_some("--lazy"))
            .map(OsString::from)
            .collect(),
    };

    args.extend([format!("--uid={uid}").into(), format!("--gid={gid}").into()]);

    let mut mountpoint_arg = OsString::from("--mountpoint=");
    mountpoint_arg.push(mountpoint);
    args.push(mountpoint_arg);

    if let Some(shared_dir) = shared_dir {
        let mut refuse = OsString::from("--refuse=");
        refuse.push(shared_dir);
        args.push(refuse);
    }

    args
}

/// Run the helper with `pidfd` on stdin and a reply socket on stdout, and
/// read its one reply.
fn run_helper(
    helper: &Path,
    args: &[OsString],
    pidfd: OwnedFd,
    timeout: Duration,
) -> io::Result<HelperReply> {
    let (ours, theirs) = StdUnixStream::pair()?;

    ours.set_read_timeout(Some(timeout))?;

    let mut command = Command::new(helper);

    command
        .args(args)
        .env_clear()
        .stdin(Stdio::from(pidfd))
        .stdout(Stdio::from(OwnedFd::from(theirs)))
        .stderr(Stdio::inherit());

    let mut child = command.spawn()?;

    // The command holds the helper's end of the socket; with it gone, a helper
    // that exits without replying ends the read instead of hanging it.
    drop(command);

    let reply = read_reply(&ours).map_err(|err| match err.kind() {
        io::ErrorKind::WouldBlock => {
            io::Error::new(io::ErrorKind::TimedOut, "the mount helper did not reply")
        }
        _ => err,
    });

    if reply.is_err() {
        let _ = child.kill();
    }

    let _ = child.wait();

    reply
}

/// Pass `fuse_fd` to the requester as `SCM_RIGHTS` on a lone newline that
/// precedes the reply line.
async fn send_descriptor(client: &UiClientHandle, fuse_fd: &OwnedFd) -> io::Result<()> {
    let writer = client.writer.lock().await;
    let stream: &UnixStream = writer.as_ref();

    let sent = stream
        .async_io(Interest::WRITABLE, || {
            send_fd(stream, b"\n", fuse_fd.as_fd())
        })
        .await;

    drop(writer);
    sent
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, os::fd::OwnedFd, path::Path, time::Duration};

    use agent_sandbox_fuse::protocol::HelperReply;

    use super::{Action, helper_args, run_helper};

    fn own_pidfd() -> OwnedFd {
        agent_sandbox_sysutil::pidfd_open(std::process::id()).expect("pidfd of this process")
    }

    fn shell(script: &str) -> Vec<OsString> {
        vec!["-c".into(), script.into()]
    }

    #[test]
    fn helper_refusal_text_reaches_the_caller() {
        let reply = run_helper(
            Path::new("/bin/sh"),
            &shell("printf 'Enot yours'"),
            own_pidfd(),
            Duration::from_secs(10),
        )
        .expect("helper replies");

        assert!(matches!(reply, HelperReply::Refused(reason) if reason == "not yours"));
    }

    #[test]
    fn helper_unmount_reply_is_read() {
        let reply = run_helper(
            Path::new("/bin/sh"),
            &shell("printf U"),
            own_pidfd(),
            Duration::from_secs(10),
        )
        .expect("helper replies");

        assert!(matches!(reply, HelperReply::Unmounted));
    }

    #[test]
    fn helper_exit_without_reply_is_an_error() {
        let error = run_helper(
            Path::new("/bin/sh"),
            &shell("exit 3"),
            own_pidfd(),
            Duration::from_secs(10),
        )
        .expect_err("no reply");

        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn silent_helper_is_killed_at_the_timeout() {
        let error = run_helper(
            Path::new("/bin/sh"),
            &shell("while :; do :; done"),
            own_pidfd(),
            Duration::from_millis(200),
        )
        .expect_err("timeout");

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn helper_arguments_name_identity_mountpoint_and_shared_dir() {
        let args = helper_args(
            &Action::Mount {
                options: "-o,x".into(),
            },
            1000,
            100,
            Path::new("/home/u/mnt"),
            Some(Path::new("/run/agent-sandbox/shared")),
        );

        let args: Vec<_> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(args, [
            "mount",
            "--options=-o,x",
            "--uid=1000",
            "--gid=100",
            "--mountpoint=/home/u/mnt",
            "--refuse=/run/agent-sandbox/shared",
        ]);
    }
}
