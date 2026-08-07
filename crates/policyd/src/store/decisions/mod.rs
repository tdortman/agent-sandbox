//! Policy store: approve/deny pending decisions.

mod approve;

mod approve_host;
mod wire;
pub use wire::DecisionAction;
