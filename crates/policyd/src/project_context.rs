//! Stateful project-attribution authority.

#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    ActivationHandle, BindingHandle, ClaimHandle, ContextAdapterErrorCode, ExternalOperationKey,
    ExternalSessionKey, WorkspaceActivation,
};

const MAX_ACTIVATIONS_PER_SANDBOX: usize = 256;
const MAX_BINDINGS_PER_ADAPTER: usize = 4096;
const MAX_OVERRIDES_PER_ADAPTER: usize = 1024;
const CLAIM_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectContextError {
    pub(crate) code: ContextAdapterErrorCode,
    pub(crate) detail: &'static str,
}

type Result<T> = std::result::Result<T, ProjectContextError>;

fn error(code: ContextAdapterErrorCode, detail: &'static str) -> ProjectContextError {
    ProjectContextError { code, detail }
}

#[derive(Debug)]
struct ActivationRecord {
    sandbox: String,
    owner_uid: u32,
    canonical_path: PathBuf,
    directory: File,
    device: u64,
    inode: u64,
}

impl ActivationRecord {
    fn open(sandbox: String, owner_uid: u32, root: &Path) -> Result<Self> {
        if !root.is_absolute() {
            return Err(error(
                ContextAdapterErrorCode::InvalidWorkspace,
                "workspace root is not absolute",
            ));
        }
        let canonical_path = root.canonicalize().map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidWorkspace,
                "workspace root cannot be canonicalised",
            )
        })?;
        let directory = File::open(&canonical_path).map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidWorkspace,
                "workspace root cannot be opened",
            )
        })?;
        let metadata = directory.metadata().map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidWorkspace,
                "workspace metadata is unavailable",
            )
        })?;
        if !metadata.is_dir() || metadata.uid() != owner_uid {
            return Err(error(
                ContextAdapterErrorCode::InvalidWorkspace,
                "workspace owner or type is invalid",
            ));
        }
        Ok(Self {
            sandbox,
            owner_uid,
            canonical_path,
            device: metadata.dev(),
            inode: metadata.ino(),
            directory,
        })
    }

    fn is_live(&self) -> bool {
        let Ok(path) = self.canonical_path.metadata() else {
            return false;
        };
        let Ok(held) = self.directory.metadata() else {
            return false;
        };
        path.is_dir()
            && path.uid() == self.owner_uid
            && path.dev() == self.device
            && path.ino() == self.inode
            && held.dev() == self.device
            && held.ino() == self.inode
    }

    fn wire(&self, handle: ActivationHandle) -> WorkspaceActivation {
        WorkspaceActivation {
            activation: handle,
            canonical_path: self.canonical_path.clone(),
        }
    }
}

#[derive(Debug)]
struct AdapterState {
    sandbox: String,
    sessions: HashMap<ExternalSessionKey, SessionBinding>,
    operations: HashMap<ExternalOperationKey, OperationIdentity>,
    released_claims: HashSet<ClaimHandle>,
}

#[derive(Debug)]
struct SessionBinding {
    activation: ActivationHandle,
    handle: BindingHandle,
    released: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperationIdentity {
    binding: BindingHandle,
    activation: ActivationHandle,
    claim: ClaimHandle,
}

#[derive(Debug)]
struct BindingRecord {
    connection_id: u64,
    activation: ActivationHandle,
}

#[derive(Debug)]
struct ClaimRecord {
    connection_id: u64,
    binding: BindingHandle,
    activation: ActivationHandle,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedWorkspace {
    pub(crate) activation: ActivationHandle,
    pub(crate) canonical_path: PathBuf,
    pub(crate) source: AttributionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributionSource {
    SessionBinding,
    OperationOverride,
}

#[derive(Debug)]
pub(crate) struct ProjectContextRegistry {
    boot_epoch: u64,
    activations: HashMap<ActivationHandle, ActivationRecord>,
    adapters: HashMap<u64, AdapterState>,
    adapter_by_sandbox: HashMap<String, u64>,
    bindings: HashMap<BindingHandle, BindingRecord>,
    claims: HashMap<ClaimHandle, ClaimRecord>,
}

impl Default for ProjectContextRegistry {
    fn default() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        Self {
            boot_epoch: u64::from_le_bytes(bytes[..8].try_into().expect("eight-byte UUID prefix")),
            activations: HashMap::new(),
            adapters: HashMap::new(),
            adapter_by_sandbox: HashMap::new(),
            bindings: HashMap::new(),
            claims: HashMap::new(),
        }
    }
}

impl ProjectContextRegistry {
    pub(crate) const fn boot_epoch(&self) -> u64 {
        self.boot_epoch
    }

    pub(crate) fn activate(
        &mut self,
        sandbox: &str,
        owner_uid: u32,
        root: &Path,
    ) -> Result<WorkspaceActivation> {
        let record = ActivationRecord::open(sandbox.to_owned(), owner_uid, root)?;
        if let Some((handle, current)) = self.activations.iter().find(|(_, current)| {
            current.sandbox == sandbox && current.canonical_path == record.canonical_path
        }) {
            if current.is_live() {
                return Ok(current.wire(handle.clone()));
            }
        }
        if self
            .activations
            .values()
            .filter(|a| a.sandbox == sandbox)
            .count()
            >= MAX_ACTIVATIONS_PER_SANDBOX
        {
            return Err(error(
                ContextAdapterErrorCode::ResourceExhausted,
                "activation limit reached",
            ));
        }
        let handle = ActivationHandle::new();
        let wire = record.wire(handle.clone());
        self.activations.insert(handle, record);
        Ok(wire)
    }

    pub(crate) fn deactivate(&mut self, activation: &ActivationHandle) {
        if self.activations.remove(activation).is_none() {
            return;
        }
        let dead_bindings: Vec<_> = self
            .bindings
            .iter()
            .filter(|(_, binding)| &binding.activation == activation)
            .map(|(handle, _)| handle.clone())
            .collect();
        for binding in dead_bindings {
            self.release_binding(&binding);
        }
    }

    pub(crate) fn register_adapter(
        &mut self,
        connection_id: u64,
        sandbox: &str,
    ) -> Result<Vec<WorkspaceActivation>> {
        if self.adapters.contains_key(&connection_id)
            || self.adapter_by_sandbox.contains_key(sandbox)
        {
            return Err(error(
                ContextAdapterErrorCode::Conflict,
                "context adapter is already registered",
            ));
        }
        self.adapters.insert(connection_id, AdapterState {
            sandbox: sandbox.to_owned(),
            sessions: HashMap::new(),
            operations: HashMap::new(),
            released_claims: HashSet::new(),
        });
        self.adapter_by_sandbox
            .insert(sandbox.to_owned(), connection_id);
        Ok(self
            .activations
            .iter()
            .filter(|(_, activation)| activation.sandbox == sandbox && activation.is_live())
            .map(|(handle, activation)| activation.wire(handle.clone()))
            .collect())
    }

    pub(crate) fn disconnect_adapter(&mut self, connection_id: u64) {
        let Some(adapter) = self.adapters.remove(&connection_id) else {
            return;
        };
        self.adapter_by_sandbox.remove(&adapter.sandbox);
        let bindings: Vec<_> = self
            .bindings
            .iter()
            .filter(|(_, record)| record.connection_id == connection_id)
            .map(|(handle, _)| handle.clone())
            .collect();
        for binding in bindings {
            self.release_binding(&binding);
        }
        self.claims
            .retain(|_, claim| claim.connection_id != connection_id);
    }

    pub(crate) fn bind_session(
        &mut self,
        connection_id: u64,
        session_key: ExternalSessionKey,
        activation: ActivationHandle,
    ) -> Result<BindingHandle> {
        self.require_activation(connection_id, &activation)?;
        let adapter = self.adapters.get_mut(&connection_id).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::Unauthorized,
                "connection is not a context adapter",
            )
        })?;
        if let Some(existing) = adapter.sessions.get(&session_key) {
            if !existing.released && existing.activation == activation {
                return Ok(existing.handle.clone());
            }
            return Err(error(
                ContextAdapterErrorCode::Conflict,
                "session binding is immutable",
            ));
        }
        if adapter.sessions.len() >= MAX_BINDINGS_PER_ADAPTER {
            return Err(error(
                ContextAdapterErrorCode::ResourceExhausted,
                "binding limit reached",
            ));
        }
        let handle = BindingHandle::new();
        adapter.sessions.insert(session_key, SessionBinding {
            activation: activation.clone(),
            handle: handle.clone(),
            released: false,
        });
        self.bindings.insert(handle.clone(), BindingRecord {
            connection_id,
            activation,
        });
        Ok(handle)
    }

    pub(crate) fn begin_operation(
        &mut self,
        connection_id: u64,
        operation_key: ExternalOperationKey,
        binding: BindingHandle,
        activation: ActivationHandle,
        now: Instant,
    ) -> Result<ClaimHandle> {
        self.expire_claims(now);
        self.require_binding(connection_id, &binding)?;
        self.require_activation(connection_id, &activation)?;
        let adapter = self.adapters.get_mut(&connection_id).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::Unauthorized,
                "connection is not a context adapter",
            )
        })?;
        if let Some(existing) = adapter.operations.get(&operation_key) {
            if existing.binding == binding
                && existing.activation == activation
                && self.claims.contains_key(&existing.claim)
            {
                return Ok(existing.claim.clone());
            }
            return Err(error(
                ContextAdapterErrorCode::Conflict,
                "operation key is already live",
            ));
        }
        if adapter.operations.len() >= MAX_OVERRIDES_PER_ADAPTER {
            return Err(error(
                ContextAdapterErrorCode::ResourceExhausted,
                "override limit reached",
            ));
        }
        let claim = ClaimHandle::new();
        adapter.operations.insert(operation_key, OperationIdentity {
            binding: binding.clone(),
            activation: activation.clone(),
            claim: claim.clone(),
        });
        self.claims.insert(claim.clone(), ClaimRecord {
            connection_id,
            binding,
            activation,
            expires_at: now + CLAIM_TTL,
        });
        Ok(claim)
    }

    pub(crate) fn release_binding_for(
        &mut self,
        connection_id: u64,
        binding: &BindingHandle,
    ) -> Result<()> {
        let adapter = self.adapters.get(&connection_id).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::Unauthorized,
                "connection is not a context adapter",
            )
        })?;
        let session = adapter
            .sessions
            .values()
            .find(|session| &session.handle == binding)
            .ok_or_else(|| {
                error(
                    ContextAdapterErrorCode::UnknownHandle,
                    "binding is unknown on this connection",
                )
            })?;
        if !session.released {
            self.release_binding(binding);
        }
        Ok(())
    }

    pub(crate) fn release_claim_for(
        &mut self,
        connection_id: u64,
        claim: &ClaimHandle,
    ) -> Result<()> {
        let adapter = self.adapters.get(&connection_id).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::Unauthorized,
                "connection is not a context adapter",
            )
        })?;
        if adapter.released_claims.contains(claim) {
            return Ok(());
        }
        if !adapter
            .operations
            .values()
            .any(|operation| &operation.claim == claim)
        {
            return Err(error(
                ContextAdapterErrorCode::UnknownHandle,
                "claim is unknown on this connection",
            ));
        }
        self.release_claim(claim);
        Ok(())
    }

    pub(crate) fn release_binding(&mut self, binding: &BindingHandle) {
        let Some(record) = self.bindings.remove(binding) else {
            return;
        };
        if let Some(adapter) = self.adapters.get_mut(&record.connection_id) {
            for session in adapter
                .sessions
                .values_mut()
                .filter(|s| &s.handle == binding)
            {
                session.released = true;
            }
            let claims: Vec<_> = adapter
                .operations
                .values()
                .filter(|operation| &operation.binding == binding)
                .map(|operation| operation.claim.clone())
                .collect();
            adapter
                .operations
                .retain(|_, operation| &operation.binding != binding);
            adapter.released_claims.extend(claims.iter().cloned());
            for claim in claims {
                self.claims.remove(&claim);
            }
        }
    }

    pub(crate) fn release_claim(&mut self, claim: &ClaimHandle) {
        self.claims.remove(claim);
        for adapter in self.adapters.values_mut() {
            if adapter
                .operations
                .values()
                .any(|operation| &operation.claim == claim)
            {
                adapter.released_claims.insert(claim.clone());
            }
            adapter
                .operations
                .retain(|_, operation| &operation.claim != claim);
        }
    }

    pub(crate) fn resolve_binding(
        &mut self,
        connection_id: u64,
        binding: &BindingHandle,
    ) -> Option<ResolvedWorkspace> {
        let activation = self
            .require_binding(connection_id, binding)
            .ok()?
            .activation
            .clone();
        self.resolve_activation(activation, AttributionSource::SessionBinding)
    }

    pub(crate) fn resolve_claim(
        &mut self,
        connection_id: u64,
        claim: &ClaimHandle,
        now: Instant,
    ) -> Option<ResolvedWorkspace> {
        self.expire_claims(now);
        let record = self.claims.get(claim)?;
        if record.connection_id != connection_id || !self.bindings.contains_key(&record.binding) {
            return None;
        }
        self.resolve_activation(
            record.activation.clone(),
            AttributionSource::OperationOverride,
        )
    }

    fn require_binding(
        &self,
        connection_id: u64,
        binding: &BindingHandle,
    ) -> Result<&BindingRecord> {
        self.bindings
            .get(binding)
            .filter(|binding| binding.connection_id == connection_id)
            .ok_or_else(|| {
                error(
                    ContextAdapterErrorCode::UnknownHandle,
                    "binding is unknown on this connection",
                )
            })
    }

    fn require_activation(
        &self,
        connection_id: u64,
        handle: &ActivationHandle,
    ) -> Result<&ActivationRecord> {
        let adapter = self.adapters.get(&connection_id).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::Unauthorized,
                "connection is not a context adapter",
            )
        })?;
        let activation = self.activations.get(handle).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::UnknownHandle,
                "activation is unknown",
            )
        })?;
        if activation.sandbox != adapter.sandbox || !activation.is_live() {
            return Err(error(
                ContextAdapterErrorCode::InvalidWorkspace,
                "activation is not live for this sandbox",
            ));
        }
        Ok(activation)
    }

    fn resolve_activation(
        &mut self,
        handle: ActivationHandle,
        source: AttributionSource,
    ) -> Option<ResolvedWorkspace> {
        let activation = self.activations.get(&handle)?;
        if !activation.is_live() {
            self.deactivate(&handle);
            return None;
        }
        Some(ResolvedWorkspace {
            activation: handle,
            canonical_path: activation.canonical_path.clone(),
            source,
        })
    }

    fn expire_claims(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .claims
            .iter()
            .filter(|(_, claim)| claim.expires_at <= now)
            .map(|(handle, _)| handle.clone())
            .collect();
        for claim in expired {
            self.release_claim(&claim);
        }
    }
}

impl crate::store::PolicyStore {
    pub(crate) fn activate_workspace(
        &self,
        sandbox: &str,
        owner_uid: u32,
        root: &Path,
    ) -> Result<WorkspaceActivation> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .activate(sandbox, owner_uid, root)
    }

    pub(crate) fn register_context_adapter(
        &self,
        connection_id: u64,
        sandbox: &str,
    ) -> Result<Vec<WorkspaceActivation>> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .register_adapter(connection_id, sandbox)
    }

    pub(crate) fn bind_project_session(
        &self,
        connection_id: u64,
        key: ExternalSessionKey,
        activation: ActivationHandle,
    ) -> Result<BindingHandle> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bind_session(connection_id, key, activation)
    }

    pub(crate) fn begin_project_operation(
        &self,
        connection_id: u64,
        key: ExternalOperationKey,
        binding: BindingHandle,
        activation: ActivationHandle,
    ) -> Result<ClaimHandle> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .begin_operation(connection_id, key, binding, activation, Instant::now())
    }

    pub(crate) fn project_context_boot_epoch(&self) -> u64 {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .boot_epoch()
    }

    pub(crate) fn release_project_binding(
        &self,
        connection_id: u64,
        binding: &BindingHandle,
    ) -> Result<()> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release_binding_for(connection_id, binding)
    }

    pub(crate) fn release_project_claim(
        &self,
        connection_id: u64,
        claim: &ClaimHandle,
    ) -> Result<()> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .release_claim_for(connection_id, claim)
    }

    pub(crate) fn disconnect_context_adapter(&self, connection_id: u64) {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .disconnect_adapter(connection_id);
    }

    pub(crate) fn resolve_project_binding(
        &self,
        connection_id: u64,
        binding: &BindingHandle,
    ) -> Option<ResolvedWorkspace> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve_binding(connection_id, binding)
    }

    pub(crate) fn resolve_project_claim(
        &self,
        connection_id: u64,
        claim: &ClaimHandle,
    ) -> Option<ResolvedWorkspace> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve_claim(connection_id, claim, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bindings_are_immutable_and_claims_do_not_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let owner = dir.path().metadata().unwrap().uid();
        let mut registry = ProjectContextRegistry::default();
        let first = registry.activate("sandbox", owner, dir.path()).unwrap();
        let snapshot = registry.register_adapter(7, "sandbox").unwrap();
        assert_eq!(snapshot, vec![first.clone()]);
        let key = ExternalSessionKey::new("thread").unwrap();
        let binding = registry
            .bind_session(7, key.clone(), first.activation.clone())
            .unwrap();
        assert_eq!(
            registry
                .bind_session(7, key, first.activation.clone())
                .unwrap(),
            binding
        );
        let claim = registry
            .begin_operation(
                7,
                ExternalOperationKey::new("turn").unwrap(),
                binding.clone(),
                first.activation,
                Instant::now(),
            )
            .unwrap();
        assert_eq!(
            registry
                .resolve_claim(7, &claim, Instant::now())
                .unwrap()
                .source,
            AttributionSource::OperationOverride
        );
        registry.release_claim_for(7, &claim).unwrap();
        registry.release_claim_for(7, &claim).unwrap();
        assert!(registry.resolve_claim(7, &claim, Instant::now()).is_none());
        assert_eq!(
            registry.resolve_binding(7, &binding).unwrap().source,
            AttributionSource::SessionBinding
        );
        registry.release_binding_for(7, &binding).unwrap();
        registry.release_binding_for(7, &binding).unwrap();
        assert!(registry.resolve_binding(7, &binding).is_none());
    }
}
