//! Shared session context for policyd and enforcement daemons.

use std::env;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionContext {
    pub cwd: Option<String>,
    pub home: Option<String>,
    pub project_root: Option<String>,
}

pub fn session_context_path() -> PathBuf {
    env::var("AGENT_SANDBOX_SESSION_CONTEXT_PATH").map_or_else(
        |_| PathBuf::from("/run/agent-sandbox/session-context.json"),
        PathBuf::from,
    )
}

#[must_use]
pub fn read_session_context() -> SessionContext {
    let path = session_context_path();
    let Ok(data) = std::fs::read_to_string(&path) else {
        return SessionContext::default();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

pub fn write_session_context(ctx: &SessionContext) {
    let path = session_context_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("tmp");
    if let Ok(json) = serde_json::to_string_pretty(ctx)
        && std::fs::write(&tmp, format!("{json}\n")).is_ok()
    {
        let _ = std::fs::rename(&tmp, &path);
    }
}
