//! Wire envelope for replies and UI pushes.

use super::{push::UiPush, reply::RpcReply};

use serde::{Deserialize, Serialize};
use std::fmt;

/// Outgoing RPC / UI push message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcMessage {
    Reply(RpcReply),
    UiPush(UiPush),
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
