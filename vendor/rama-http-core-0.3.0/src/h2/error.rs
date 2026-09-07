use std::{error, fmt, io};

use rama_core::bytes::Bytes;
pub use rama_http_types::proto::h2::frame::Reason;
use rama_http_types::proto::h2::frame::StreamId;

use crate::h2::{
    codec::{SendError, UserError},
    proto::{self, Initiator},
};

/// Represents HTTP/2 operation errors.
///
/// `Error` covers error cases raised by protocol errors caused by the
/// peer, I/O (transport) errors, and errors caused by the user of the library.
///
/// If the error was caused by the remote peer, then it will contain a
/// [`Reason`] which can be obtained with the [`reason`] function.
///
/// [`Reason`]: struct.Reason.html
/// [`reason`]: #method.reason
#[derive(Debug)]
pub struct Error {
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    /// A RST_STREAM frame was received or sent.
    #[expect(dead_code)]
    Reset(StreamId, Reason, Initiator),

    /// A GO_AWAY frame was received or sent.
    // The final flag is true only for streams above a remote GOAWAY limit.
    GoAway(Bytes, Reason, Initiator, bool),

    /// The user created an error from a bare Reason.
    Reason(Reason),

    /// An error resulting from an invalid action taken by the user of this
    /// library.
    User(UserError),

    /// An `io::Error` occurred while trying to read or write.
    Io(io::Error),
}

// ===== impl Error =====

impl Error {
    /// If the error was caused by the remote peer, the error reason.
    ///
    /// This is either an error received by the peer or caused by an invalid
    /// action taken by the peer (i.e. a protocol error).
    pub fn reason(&self) -> Option<Reason> {
        match self.kind {
            Kind::Reset(_, reason, _) | Kind::GoAway(_, reason, ..) | Kind::Reason(reason) => {
                Some(reason)
            }
            _ => None,
        }
    }

    /// Whether the peer guarantees this request was not processed.
    /// This does not guarantee that the caller can replay its request body.
    pub fn is_unprocessed(&self) -> bool {
        matches!(
            self.kind,
            Kind::Reset(_, Reason::REFUSED_STREAM, Initiator::Remote)
                | Kind::GoAway(_, _, Initiator::Remote, true)
        )
    }

    /// Returns true if the error is an io::Error
    pub fn is_io(&self) -> bool {
        matches!(self.kind, Kind::Io(..))
    }

    /// Returns the error if the error is an io::Error
    pub fn get_io(&self) -> Option<&io::Error> {
        match self.kind {
            Kind::Io(ref e) => Some(e),
            _ => None,
        }
    }

    /// Return the underlying io::Error or else return self as Err.
    pub fn try_into_io(self) -> Result<io::Error, Self> {
        match self.kind {
            Kind::Io(e) => Ok(e),
            _ => Err(self),
        }
    }

    /// Returns the error if the error is an io::Error
    #[inline(always)]
    pub fn into_io(self) -> Option<io::Error> {
        self.try_into_io().ok()
    }

    /// Return the underlying io::Error or otherwise
    /// it will cast it as an "other" IO Error
    #[inline(always)]
    pub fn force_into_io(self) -> io::Error {
        self.try_into_io().unwrap_or_else(std::io::Error::other)
    }

    pub(crate) fn from_io(err: io::Error) -> Self {
        Self {
            kind: Kind::Io(err),
        }
    }

    /// Returns true if the error is from a `GOAWAY`.
    pub fn is_go_away(&self) -> bool {
        matches!(self.kind, Kind::GoAway(..))
    }

    /// Returns true if the error is from a `RST_STREAM`.
    pub fn is_reset(&self) -> bool {
        matches!(self.kind, Kind::Reset(..))
    }

    /// Returns true if the error was received in a frame from the remote.
    ///
    /// Such as from a received `RST_STREAM` or `GOAWAY` frame.
    pub fn is_remote(&self) -> bool {
        matches!(
            self.kind,
            Kind::GoAway(_, _, Initiator::Remote, _) | Kind::Reset(_, _, Initiator::Remote)
        )
    }

    /// Returns true if the error was created by `h2`.
    ///
    /// Such as noticing some protocol error and sending a GOAWAY or RST_STREAM.
    pub fn is_library(&self) -> bool {
        matches!(
            self.kind,
            Kind::GoAway(_, _, Initiator::Library, _) | Kind::Reset(_, _, Initiator::Library)
        )
    }
}

impl From<proto::Error> for Error {
    fn from(src: proto::Error) -> Self {
        Self {
            kind: match src {
                proto::Error::Reset(stream_id, reason, initiator) => {
                    Kind::Reset(stream_id, reason, initiator)
                }
                proto::Error::GoAway(debug_data, reason, initiator, unprocessed) => {
                    Kind::GoAway(debug_data, reason, initiator, unprocessed)
                }
                proto::Error::Io(kind, inner) => {
                    Kind::Io(inner.map_or_else(|| kind.into(), |inner| io::Error::new(kind, inner)))
                }
                proto::Error::User(err) => Kind::User(err),
            },
        }
    }
}

impl From<Reason> for Error {
    fn from(src: Reason) -> Self {
        Self {
            kind: Kind::Reason(src),
        }
    }
}

impl From<SendError> for Error {
    fn from(src: SendError) -> Self {
        match src {
            SendError::User(e) => e.into(),
            SendError::Connection(e) => e.into(),
        }
    }
}

impl From<UserError> for Error {
    fn from(src: UserError) -> Self {
        Self {
            kind: Kind::User(src),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let debug_data = match self.kind {
            Kind::Reset(_, reason, Initiator::User) => {
                return write!(fmt, "stream error sent by user: {reason}");
            }
            Kind::Reset(_, reason, Initiator::Library) => {
                return write!(fmt, "stream error detected: {reason}");
            }
            Kind::Reset(_, reason, Initiator::Remote) => {
                return write!(fmt, "stream error received: {reason}");
            }
            Kind::GoAway(ref debug_data, reason, Initiator::User, _) => {
                write!(fmt, "connection error sent by user: {reason}")?;
                debug_data
            }
            Kind::GoAway(ref debug_data, reason, Initiator::Library, _) => {
                write!(fmt, "connection error detected: {reason}")?;
                debug_data
            }
            Kind::GoAway(ref debug_data, reason, Initiator::Remote, _) => {
                write!(fmt, "connection error received: {reason}")?;
                debug_data
            }
            Kind::Reason(reason) => return write!(fmt, "protocol error: {reason}"),
            Kind::User(ref e) => return write!(fmt, "user error: {e}"),
            Kind::Io(ref e) => return e.fmt(fmt),
        };

        if !debug_data.is_empty() {
            write!(fmt, " ({debug_data:?})")?;
        }

        Ok(())
    }
}

impl error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::h2::error::Reason;

    #[test]
    fn error_from_reason() {
        let err = Error::from(Reason::HTTP_1_1_REQUIRED);
        assert_eq!(err.reason(), Some(Reason::HTTP_1_1_REQUIRED));
    }
}
