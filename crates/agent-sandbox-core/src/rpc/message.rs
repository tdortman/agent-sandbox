//! Wire envelope for replies and UI pushes.

use serde::{Deserialize, Serialize};

use super::push::UiPush;
use super::reply::RpcReply;

/// Outgoing RPC / UI push message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcMessage {
    Reply(RpcReply),
    UiPush(UiPush),
}

impl RpcMessage {
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default() + "\n"
    }
}
