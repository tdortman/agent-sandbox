//! The one message the mount helper sends back to policyd over its stdout
//! socket.

use std::{
    io,
    os::fd::{AsFd, OwnedFd},
};

use agent_sandbox_sysutil::{recv_with_fds, send_fd};

/// Read buffer for a reply: a tag byte plus a refusal text.
const REPLY_BUFFER_BYTES: usize = 512;

/// Most characters of a refusal text carried back; four bytes each still fit
/// the read buffer.
const MAX_REASON_CHARS: usize = 120;

/// What the helper did.
#[derive(Debug)]
pub enum HelperReply {
    /// The filesystem is mounted; the `/dev/fuse` descriptor rides along.
    Mounted(OwnedFd),

    /// The filesystem is unmounted.
    Unmounted,

    /// The helper refused or failed, with a reason fit to show the user.
    Refused(String),
}

/// Send `reply` on `sock`.
///
/// # Errors
/// Returns the socket error.
pub fn send_reply(sock: impl AsFd, reply: &HelperReply) -> io::Result<()> {
    let message = match reply {
        HelperReply::Mounted(fd) => return send_fd(sock, b"M", fd.as_fd()),
        HelperReply::Unmounted => "U".to_owned(),
        HelperReply::Refused(reason) => {
            format!(
                "E{}",
                reason.chars().take(MAX_REASON_CHARS).collect::<String>()
            )
        }
    };

    rustix::io::write(sock, message.as_bytes())
        .map(drop)
        .map_err(io::Error::from)
}

/// Read the helper's reply from `sock`.
///
/// # Errors
/// Returns the socket error, or `UnexpectedEof` when the helper exited without
/// replying and `InvalidData` for a message it should not send.
pub fn read_reply(sock: impl AsFd) -> io::Result<HelperReply> {
    let mut buf = [0_u8; REPLY_BUFFER_BYTES];
    let received = recv_with_fds(sock, &mut buf)?;
    let body = &buf[..received.len];

    match (body.split_first(), received.fds.into_iter().next()) {
        (Some((b'M', _)), Some(fd)) => Ok(HelperReply::Mounted(fd)),
        (Some((b'U', _)), None) => Ok(HelperReply::Unmounted),
        (Some((b'E', reason)), None) => Ok(HelperReply::Refused(
            String::from_utf8_lossy(reason).into_owned(),
        )),
        (None, _) => Err(io::ErrorKind::UnexpectedEof.into()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected mount helper reply",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::os::{fd::AsFd, unix::net::UnixStream};

    use super::{HelperReply, read_reply, send_reply};

    #[test]
    fn mounted_reply_carries_the_descriptor() {
        let (helper, policyd) = UnixStream::pair().expect("socket pair");
        let file = std::fs::File::open("/dev/null").expect("open");

        send_reply(
            &helper,
            &HelperReply::Mounted(file.as_fd().try_clone_to_owned().expect("dup")),
        )
        .expect("send");

        assert!(matches!(
            read_reply(&policyd).expect("read"),
            HelperReply::Mounted(_)
        ));
    }

    #[test]
    fn refusal_and_unmount_round_trip() {
        let (helper, policyd) = UnixStream::pair().expect("socket pair");

        send_reply(&helper, &HelperReply::Refused("not yours".into())).expect("send");
        assert!(matches!(
            read_reply(&policyd).expect("read"),
            HelperReply::Refused(reason) if reason == "not yours"
        ));

        send_reply(&helper, &HelperReply::Unmounted).expect("send");
        assert!(matches!(
            read_reply(&policyd).expect("read"),
            HelperReply::Unmounted
        ));
    }

    #[test]
    fn helper_exit_without_a_reply_is_an_error() {
        let (helper, policyd) = UnixStream::pair().expect("socket pair");
        drop(helper);

        assert_eq!(
            read_reply(&policyd).expect_err("no reply").kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}
