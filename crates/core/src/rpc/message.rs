//! Wire envelope for replies and UI pushes.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{push::UiPush, reply::RpcReply};

/// Liveness line policyd writes while it is still working on a request.
///
/// Sent only on connections whose request opted in with the `heartbeat`
/// field (see `HEARTBEAT_FIELD`): a client that predates heartbeats cannot
/// decode this line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Heartbeat {
    /// policyd is alive and still working on the in-flight request.
    #[serde(rename = "heartbeat")]
    Alive,
}

/// Outgoing RPC / UI push message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcMessage {
    /// A reply to an in-flight RPC request.
    Reply(RpcReply),

    /// A UI push sent unsolicited to clients.
    UiPush(UiPush),

    /// A liveness line for an in-flight request that opted in.
    Heartbeat(Heartbeat),
}

impl RpcMessage {
    /// # Errors
    ///
    /// Returns the JSON serialization error when the message cannot be encoded.
    pub fn encode_line(&self) -> Result<String, serde_json::Error> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }
}

impl fmt::Display for RpcMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let line = self.encode_line().map_err(|_| fmt::Error)?;
        f.write_str(&line)
    }
}

#[cfg(test)]
mod tests {
    use super::{Heartbeat, RpcMessage};
    use crate::rpc::UiPush;

    #[test]
    fn heartbeat_line_round_trips_as_its_own_message() {
        let line = RpcMessage::Heartbeat(Heartbeat::Alive).to_string();
        assert_eq!(line, "{\"type\":\"heartbeat\"}\n");
        assert!(matches!(
            serde_json::from_str(line.trim_end()),
            Ok(RpcMessage::Heartbeat(Heartbeat::Alive))
        ));
    }

    #[test]
    fn display_serializes_json_line() {
        let message = RpcMessage::UiPush(UiPush::NetworkRequest {
            id: "n1".into(),
            host: Some("host".into()),
            port: Some(443),
            scheme: None,
            url: None,
            cwd: None,
            home: None,
            project_root: None,

            package: None,
        });

        assert!(message.to_string().ends_with('\n'));
    }
}
