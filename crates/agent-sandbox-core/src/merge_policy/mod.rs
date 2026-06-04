//! Merge agent-sandbox policy layers (later layers win on duplicate keys).

mod io;
mod merge;
mod project;

#[cfg(test)]
mod tests;

pub use io::{
    atomic_write_policy, chown_policy_path, load_policy, resolve_owner_uid,
    resolve_policy_write_path,
};
pub use merge::{merge_layers, network_rule_key, sudo_rule_key};
pub use project::{
    discover_project_policy, infer_home_from_paths, is_ephemeral_cwd, is_valid_project_root,
    project_policy_paths, resolve_project_policy_path,
};
