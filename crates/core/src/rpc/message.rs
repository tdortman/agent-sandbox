//! Wire envelope for replies and UI pushes.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{push::UiPush, reply::RpcReply};

/// Outgoing RPC / UI push message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcMessage {
    Reply(RpcReply),
    UiPush(UiPush),
}

impl RpcMessage {
    fn encode_line(&self) -> String {
        let mut line = serde_json::to_string(self).unwrap_or_default();
        line.push('\n');
        line
    }
}

impl fmt::Display for RpcMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode_line())
    }
}

#[cfg(test)]
mod tests {
    use super::RpcMessage;
    use crate::rpc::UiPush;

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
        });
        assert!(message.to_string().ends_with('\n'));
    }
}
