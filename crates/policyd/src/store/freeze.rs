//! Privileged host-side cgroup freezer for interactive approvals.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tracing::warn;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const DEFAULT_REGISTRY: &str = "/run/agent-sandbox/cgroup-freeze";

#[derive(Debug, thiserror::Error)]
pub enum CgroupFreezeError {
    #[error("cannot read cgroup for pid {pid}: {source}")]
    ProcessCgroup { pid: u32, source: io::Error },

    #[error("pid {pid} is not in a cgroup v2 hierarchy")]
    NotCgroupV2 { pid: u32 },

    #[error("pid {pid} is not owned by uid {expected_uid} (actual uid {actual_uid})")]
    WrongOwner {
        pid: u32,
        expected_uid: u32,
        actual_uid: u32,
    },

    #[error("pid {pid} is not in an agent-sandbox systemd scope: {path}")]
    UnmanagedScope { pid: u32, path: PathBuf },

    #[error("cgroup freezer path is invalid: {0}")]
    InvalidPath(PathBuf),

    #[error("cannot freeze cgroup {path}: {source}")]
    Freeze { path: PathBuf, source: io::Error },

    #[error("cannot persist cgroup freeze state: {0}")]
    Registry(#[source] io::Error),
}
#[derive(Clone)]
pub struct CgroupFreezeManager {
    state: Arc<Mutex<FreezeState>>,
}

struct FreezeState {
    holds: HashMap<PathBuf, usize>,
    registry: PathBuf,
}

pub struct CgroupFreezeHold {
    manager: CgroupFreezeManager,
    path: Option<PathBuf>,
}

impl CgroupFreezeManager {
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_recovery(true)
    }

    #[must_use]
    pub fn new_without_recovery() -> Self {
        Self::new_with_recovery(false)
    }

    fn new_with_recovery(recover: bool) -> Self {
        let registry = std::env::var_os("AGENT_SANDBOX_CGROUP_FREEZE_STATE")
            .map_or_else(|| PathBuf::from(DEFAULT_REGISTRY), PathBuf::from);
        if recover && let Err(error) = thaw_stale_registry(&registry) {
            warn!(%error, "failed to recover stale cgroup freeze registry");
        }
        Self {
            state: Arc::new(Mutex::new(FreezeState {
                holds: HashMap::new(),
                registry,
            })),
        }
    }

    pub fn cleanup_default_registry() -> Result<(), CgroupFreezeError> {
        let registry = std::env::var_os("AGENT_SANDBOX_CGROUP_FREEZE_STATE")
            .map_or_else(|| PathBuf::from(DEFAULT_REGISTRY), PathBuf::from);
        thaw_stale_registry(&registry)
    }

    /// Freeze the agent-sandbox scope containing `pid` and share a hold with
    /// other approvals for the same scope.
    pub fn acquire(
        &self,
        pid: Option<u32>,
        expected_uid: Option<u32>,
    ) -> Result<Option<CgroupFreezeHold>, CgroupFreezeError> {
        let Some(pid) = pid else {
            return Ok(None);
        };
        let path = cgroup_for_pid(pid, expected_uid)?;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.holds.contains_key(&path) {
            *state
                .holds
                .get_mut(&path)
                .expect("cgroup hold exists after contains_key") += 1;
            if let Err(error) = persist_registry(&state.registry, state.holds.keys()) {
                *state
                    .holds
                    .get_mut(&path)
                    .expect("cgroup hold exists after failed persistence") -= 1;
                return Err(error);
            }
        } else {
            state.holds.insert(path.clone(), 1);
            if let Err(error) = persist_registry(&state.registry, state.holds.keys()) {
                state.holds.remove(&path);
                return Err(error);
            }
            if let Err(error) = set_frozen(&path, true) {
                state.holds.remove(&path);
                let _ = persist_registry(&state.registry, state.holds.keys());
                return Err(error);
            }
        }
        drop(state);
        Ok(Some(CgroupFreezeHold {
            manager: self.clone(),
            path: Some(path),
        }))
    }

    fn release(&self, path: &Path) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state.holds.get(path).copied() {
            Some(count) if count > 1 => {
                state.holds.insert(path.to_path_buf(), count - 1);
            }
            Some(1) => match set_frozen(path, false) {
                Ok(()) => {
                    state.holds.remove(path);
                }
                Err(error) => {
                    warn!(
                        %error,
                        path = %path.display(),
                        "failed to thaw cgroup after approval; retaining recovery state"
                    );
                }
            },
            _ => {}
        }
        if let Err(error) = persist_registry(&state.registry, state.holds.keys()) {
            warn!(%error, "failed to persist cgroup freeze state after release");
        }
    }
}
/// Thaw every cgroup recorded by the previous policy daemon instance.
///
/// # Errors
///
/// Returns an error when a recorded cgroup cannot be thawed or the registry
/// cannot be removed.
pub fn cleanup_default_registry() -> Result<(), CgroupFreezeError> {
    CgroupFreezeManager::cleanup_default_registry()
}

impl Default for CgroupFreezeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CgroupFreezeHold {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            self.manager.release(&path);
        }
    }
}

fn cgroup_for_pid(pid: u32, expected_uid: Option<u32>) -> Result<PathBuf, CgroupFreezeError> {
    if let Some(expected_uid) = expected_uid {
        let actual_uid = process_uid(pid)?;
        if actual_uid != expected_uid {
            return Err(CgroupFreezeError::WrongOwner {
                pid,
                expected_uid,
                actual_uid,
            });
        }
    }
    let proc_path = format!("/proc/{pid}/cgroup");
    let contents = fs::read_to_string(&proc_path)
        .map_err(|source| CgroupFreezeError::ProcessCgroup { pid, source })?;
    let Some(relative) = contents.lines().find_map(|line| {
        let (hierarchy, path) = line.split_once("::")?;
        (hierarchy == "0").then_some(path)
    }) else {
        return Err(CgroupFreezeError::NotCgroupV2 { pid });
    };
    let path = Path::new(CGROUP_ROOT).join(relative.trim_start_matches('/'));
    if !is_agent_scope(&path) {
        return Err(CgroupFreezeError::UnmanagedScope { pid, path });
    }
    if !path.join("cgroup.freeze").is_file() {
        return Err(CgroupFreezeError::InvalidPath(path));
    }
    Ok(path)
}

fn process_uid(pid: u32) -> Result<u32, CgroupFreezeError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|source| CgroupFreezeError::ProcessCgroup { pid, source })?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| CgroupFreezeError::ProcessCgroup {
            pid,
            source: io::Error::new(io::ErrorKind::InvalidData, "missing process uid"),
        })?;
    Ok(uid)
}

fn is_agent_scope(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        name.strip_prefix("agent-sandbox-").is_some_and(|suffix| {
            Path::new(suffix)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("scope"))
        })
    })
}

fn set_frozen(path: &Path, frozen: bool) -> Result<(), CgroupFreezeError> {
    let freeze_path = path.join("cgroup.freeze");
    fs::write(&freeze_path, if frozen { "1" } else { "0" }).map_err(|source| {
        CgroupFreezeError::Freeze {
            path: path.to_path_buf(),
            source,
        }
    })
}
fn persist_registry<'a>(
    registry: &Path,
    paths: impl Iterator<Item = &'a PathBuf>,
) -> Result<(), CgroupFreezeError> {
    let Some(parent) = registry.parent() else {
        return Err(CgroupFreezeError::Registry(io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry has no parent",
        )));
    };
    fs::create_dir_all(parent).map_err(CgroupFreezeError::Registry)?;
    let mut contents = String::new();
    for path in paths {
        writeln!(&mut contents, "{}", path.display()).expect("writing to String cannot fail");
    }
    let tmp = registry.with_extension("tmp");
    fs::write(&tmp, contents).map_err(CgroupFreezeError::Registry)?;
    fs::rename(tmp, registry).map_err(CgroupFreezeError::Registry)
}

fn thaw_stale_registry(registry: &Path) -> Result<(), CgroupFreezeError> {
    let contents = match fs::read_to_string(registry) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(CgroupFreezeError::Registry(error)),
    };
    let mut first_error = None;
    for path in contents.lines().map(Path::new) {
        if !path.starts_with(CGROUP_ROOT) {
            continue;
        }
        if let Err(error) = set_frozen(path, false)
            && !matches!(error, CgroupFreezeError::Freeze { ref source, .. } if source.kind() == io::ErrorKind::NotFound)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    match fs::remove_file(registry) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CgroupFreezeError::Registry(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn manager_for(path: &Path, registry: &Path, count: usize) -> CgroupFreezeManager {
        CgroupFreezeManager {
            state: Arc::new(Mutex::new(FreezeState {
                holds: HashMap::from([(path.to_path_buf(), count)]),
                registry: registry.to_path_buf(),
            })),
        }
    }

    #[test]
    fn last_release_thaws_after_shared_holds() {
        let dir = tempdir().expect("temporary directory");
        let cgroup = dir.path().join("sandbox");
        fs::create_dir(&cgroup).expect("cgroup directory");
        fs::write(cgroup.join("cgroup.freeze"), "1").expect("freeze file");
        let manager = manager_for(&cgroup, &dir.path().join("state"), 2);

        manager.release(&cgroup);
        assert_eq!(
            fs::read_to_string(cgroup.join("cgroup.freeze")).unwrap(),
            "1"
        );
        manager.release(&cgroup);
        assert_eq!(
            fs::read_to_string(cgroup.join("cgroup.freeze")).unwrap(),
            "0"
        );
    }

    #[test]
    fn failed_thaw_retains_recovery_registry() {
        let dir = tempdir().expect("temporary directory");
        let cgroup = dir.path().join("missing");
        let registry = dir.path().join("state");
        let manager = manager_for(&cgroup, &registry, 1);

        manager.release(&cgroup);
        assert!(registry.exists());
        assert_eq!(
            fs::read_to_string(registry).unwrap().trim(),
            cgroup.display().to_string()
        );
    }

    #[test]
    fn stale_registry_cleanup_removes_missing_cgroup_entries() {
        let dir = tempdir().expect("temporary directory");
        let registry = dir.path().join("state");
        fs::write(
            &registry,
            "/sys/fs/cgroup/agent-sandbox-freeze-test-missing.scope\n",
        )
        .expect("registry");

        thaw_stale_registry(&registry).expect("missing cgroup is already thawed");

        assert!(!registry.exists());
    }
}
