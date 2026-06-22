//! Merge agent-sandbox policy layers with deny-wins semantics.

mod io;
mod merge;
mod project;

#[cfg(test)]
mod tests;

pub use io::{
    atomic_write_policy, chown_policy_path, load_policy, resolve_owner_uid,
    resolve_policy_write_path,
};
pub use merge::merge_layers;
pub use project::ProjectPolicyContext;
