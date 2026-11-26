//! Freezer state of a flow owner's cgroup.
//!
//! Policyd freezes the whole sandbox while an approval is pending. Frozen
//! processes run no userspace code, so a deadline that waits on the client
//! must not count the time the owner spends frozen.

use std::path::Path;

/// Whether a freeze is requested on the cgroup or an ancestor.
///
/// The request (`cgroup.freeze`) decides, not the `frozen` state in
/// `cgroup.events`: the kernel reports that only once every task stopped, and
/// a task waiting on a seccomp notification its frozen broker already
/// received never does. A cgroup that is gone or unreadable counts as
/// running.
#[must_use]
pub fn cgroup_frozen(cgroup: &Path) -> bool {
    cgroup.ancestors().any(|dir| {
        std::fs::read_to_string(dir.join("cgroup.freeze")).is_ok_and(|freeze| freeze.trim() == "1")
    })
}

#[cfg(test)]
mod tests {
    use super::cgroup_frozen;

    #[test]
    fn freeze_request_on_cgroup_or_ancestor_counts_as_frozen() {
        let root = tempfile::tempdir().expect("tempdir");
        let child = root.path().join("scope");
        std::fs::create_dir(&child).expect("child dir");
        std::fs::write(child.join("cgroup.freeze"), "0\n").expect("child freeze");
        assert!(!cgroup_frozen(&child));

        std::fs::write(root.path().join("cgroup.freeze"), "1\n").expect("ancestor freeze");
        assert!(cgroup_frozen(&child), "ancestor freeze covers the child");

        std::fs::write(child.join("cgroup.freeze"), "1\n").expect("child freeze");
        std::fs::write(root.path().join("cgroup.freeze"), "0\n").expect("ancestor thaw");
        assert!(cgroup_frozen(&child));
    }

    #[test]
    fn missing_cgroup_counts_as_running() {
        let root = tempfile::tempdir().expect("tempdir");
        assert!(!cgroup_frozen(&root.path().join("gone")));
    }
}
