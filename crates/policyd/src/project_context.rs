//! Stateful project-attribution authority.

#![allow(dead_code)]

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, IntoRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use agent_sandbox_core::{
    ActivationHandle, AttachmentHandle, BindingHandle, CgroupIdentity, ClaimHandle,
    ContextAdapterErrorCode, ExternalOperationKey, ExternalSessionKey, ProcessIdentity,
    WorkspaceActivation,
};

const MAX_ACTIVATIONS_PER_SANDBOX: usize = 256;
const MAX_ATTACHMENTS_PER_SANDBOX: usize = 1024;

#[derive(Debug)]
pub(crate) struct ReceivedFd(RawFd);

impl ReceivedFd {
    pub(crate) const fn new(fd: RawFd) -> Self {
        Self(fd)
    }

    pub(crate) const fn raw(&self) -> RawFd {
        self.0
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(
            agent_sandbox_sysutil::duplicate_fd(self.raw())?.into_raw_fd(),
        ))
    }
}

impl AsRawFd for ReceivedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for ReceivedFd {
    fn drop(&mut self) {
        let _ = nix::unistd::close(self.0);
    }
}
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
        let directory = File::open(root).map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidWorkspace,
                "workspace root cannot be opened",
            )
        })?;
        let canonical_path = std::fs::read_link(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| {
                error(
                    ContextAdapterErrorCode::InvalidWorkspace,
                    "workspace root cannot be canonicalised",
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
    active: bool,
}

#[derive(Debug)]
struct ProcessAttachment {
    connection_id: u64,
    context: AttachmentHandle,
    _pidfd: ReceivedFd,
    cgroup: Option<PathBuf>,
    /// Inode captured from the policyd-created binding or claim leaf.
    cgroup_identity: Option<CgroupIdentity>,
}

impl Drop for ProcessAttachment {
    fn drop(&mut self) {
        let (Some(cgroup), Some(expected)) = (&self.cgroup, self.cgroup_identity) else {
            return;
        };
        let actual = std::fs::metadata(cgroup)
            .ok()
            .and_then(|metadata| CgroupIdentity::new(metadata.ino()).ok());
        if actual == Some(expected) {
            let _ = std::fs::remove_dir(cgroup);
        }
    }
}

/// Rolls back a stopped process attachment until the cgroup move, registry
/// insertion, and resume have all succeeded.
struct AttachmentFailureGuard<'a> {
    registry: &'a Mutex<ProjectContextRegistry>,
    process: ProcessIdentity,
    pidfd: ReceivedFd,
    provisional_leaf: Option<PathBuf>,
    committed: bool,
}

impl<'a> AttachmentFailureGuard<'a> {
    fn new(
        registry: &'a Mutex<ProjectContextRegistry>,
        process: ProcessIdentity,
        pidfd: ReceivedFd,
        provisional_leaf: Option<PathBuf>,
    ) -> Self {
        Self {
            registry,
            process,
            pidfd,
            provisional_leaf,
            committed: false,
        }
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for AttachmentFailureGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        // The process is still stopped while this guard is armed. Use the
        // pidfd rather than the numeric PID, then remove any provisional
        // registry state before dropping the cgroup leaf.
        let _ = agent_sandbox_sysutil::pidfd_send_signal(self.pidfd.raw(), nix::libc::SIGKILL);
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .detach_process(&self.process);
        if let Some(leaf) = &self.provisional_leaf {
            let _ = std::fs::remove_dir(leaf);
        }
    }
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
    attachments: HashMap<ProcessIdentity, ProcessAttachment>,
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
            attachments: HashMap::new(),
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
        self.attachments
            .retain(|_, attachment| attachment.connection_id != connection_id);
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
            active: false,
        });
        Ok(claim)
    }

    pub(crate) fn adapter_sandbox(&self, connection_id: u64) -> Option<&str> {
        self.adapters
            .get(&connection_id)
            .map(|adapter| adapter.sandbox.as_str())
    }

    pub(crate) fn prepare_process_attachment(
        &mut self,
        connection_id: u64,
        process: ProcessIdentity,
        context: &AttachmentHandle,
        now: Instant,
    ) -> Result<(bool, Option<PathBuf>)> {
        self.expire_claims(now);
        match context {
            AttachmentHandle::Binding(binding) => {
                self.require_binding(connection_id, binding)?;
            }
            AttachmentHandle::Claim(claim) => {
                let record = self.claims.get(claim).ok_or_else(|| {
                    error(ContextAdapterErrorCode::UnknownHandle, "claim is unknown")
                })?;
                if record.connection_id != connection_id {
                    return Err(error(
                        ContextAdapterErrorCode::UnknownHandle,
                        "claim is unknown on this connection",
                    ));
                }
            }
        }
        if let Some(existing) = self.attachments.get(&process) {
            if existing.connection_id == connection_id && &existing.context == context {
                return Ok((true, existing.cgroup.clone()));
            }
            return Err(error(
                ContextAdapterErrorCode::Conflict,
                "process is already attached",
            ));
        }
        let matching = self.attachments.values().find(|attachment| {
            attachment.connection_id == connection_id && &attachment.context == context
        });
        if matches!(context, AttachmentHandle::Claim(_)) && matching.is_some() {
            return Err(error(
                ContextAdapterErrorCode::Conflict,
                "claim is attached to another process",
            ));
        }
        Ok((
            false,
            matching.and_then(|attachment| attachment.cgroup.clone()),
        ))
    }

    pub(crate) fn attach_process(
        &mut self,
        connection_id: u64,
        process: ProcessIdentity,
        context: AttachmentHandle,
        pidfd: ReceivedFd,
        cgroup: Option<PathBuf>,
        now: Instant,
    ) -> Result<()> {
        self.expire_claims(now);
        if let Some(existing) = self.attachments.get(&process) {
            if existing.connection_id == connection_id && existing.context == context {
                return Ok(());
            }
            return Err(error(
                ContextAdapterErrorCode::Conflict,
                "process is already attached",
            ));
        }
        let claim_to_activate = match &context {
            AttachmentHandle::Binding(binding) => {
                self.require_binding(connection_id, binding)?;
                None
            }
            AttachmentHandle::Claim(claim) => {
                let record = self.claims.get(claim).ok_or_else(|| {
                    error(ContextAdapterErrorCode::UnknownHandle, "claim is unknown")
                })?;
                if record.connection_id != connection_id {
                    return Err(error(
                        ContextAdapterErrorCode::UnknownHandle,
                        "claim is unknown on this connection",
                    ));
                }
                if self.attachments.values().any(|attachment| {
                    matches!(&attachment.context, AttachmentHandle::Claim(current) if current == claim)
                        && attachment.connection_id == connection_id
                }) {
                    return Err(error(
                        ContextAdapterErrorCode::Conflict,
                        "claim is attached to another process",
                    ));
                }
                Some(claim.clone())
            }
        };
        if self
            .attachments
            .values()
            .filter(|attachment| attachment.connection_id == connection_id)
            .count()
            >= MAX_ATTACHMENTS_PER_SANDBOX
        {
            return Err(error(
                ContextAdapterErrorCode::ResourceExhausted,
                "process attachment limit reached",
            ));
        }
        let cgroup_identity = cgroup.as_deref().and_then(|path| {
            std::fs::metadata(path)
                .ok()
                .and_then(|metadata| CgroupIdentity::new(metadata.ino()).ok())
        });
        if cgroup.is_some() && cgroup_identity.is_none() {
            return Err(error(
                ContextAdapterErrorCode::InvalidProcess,
                "controlled process cgroup identity is unavailable",
            ));
        }
        self.attachments.insert(process, ProcessAttachment {
            connection_id,
            context,
            _pidfd: pidfd,
            cgroup,
            cgroup_identity,
        });
        if let Some(claim) = claim_to_activate {
            self.claims
                .get_mut(&claim)
                .expect("validated claim remains live")
                .active = true;
        }
        Ok(())
    }

    pub(crate) fn detach_process(&mut self, process: &ProcessIdentity) {
        if let Some(attachment) = self.attachments.remove(process)
            && let AttachmentHandle::Claim(claim) = &attachment.context
            && !self.attachments.values().any(|current| {
                matches!(&current.context, AttachmentHandle::Claim(current_claim) if current_claim == claim)
            })
            && let Some(record) = self.claims.get_mut(claim)
        {
            record.active = false;
        }
    }

    pub(crate) fn attached_cgroup_for_process(
        &self,
        process: &ProcessIdentity,
        connection_id: u64,
    ) -> Option<CgroupIdentity> {
        self.attachments
            .get(process)
            .filter(|attachment| attachment.connection_id == connection_id)
            .and_then(|attachment| attachment.cgroup_identity)
    }

    pub(crate) fn resolve_attached_process(
        &mut self,
        process: &ProcessIdentity,
        cgroup: CgroupIdentity,
        connection_id: u64,
        now: Instant,
    ) -> Option<ResolvedWorkspace> {
        let attachment = if let Some(exact) = self.attachments.get(process) {
            (exact.connection_id == connection_id && exact.cgroup_identity == Some(cgroup))
                .then_some(exact)
        } else {
            self.attachments.values().find(|attachment| {
                attachment.connection_id == connection_id
                    && attachment.cgroup_identity == Some(cgroup)
            })
        }?;
        let context = attachment.context.clone();
        match context {
            AttachmentHandle::Binding(binding) => self.resolve_binding(connection_id, &binding),
            AttachmentHandle::Claim(claim) => self.resolve_claim(connection_id, &claim, now),
        }
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
            self.attachments.retain(|_, attachment| {
                !matches!(&attachment.context, AttachmentHandle::Binding(current) if current == binding)
                    && !matches!(&attachment.context, AttachmentHandle::Claim(current) if claims.contains(current))
            });
            for claim in claims {
                self.claims.remove(&claim);
            }
        }
    }

    pub(crate) fn release_claim(&mut self, claim: &ClaimHandle) {
        self.claims.remove(claim);
        self.attachments.retain(
            |_, attachment| !matches!(&attachment.context, AttachmentHandle::Claim(current) if current == claim),
        );
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
            .filter(|(_, claim)| !claim.active && claim.expires_at <= now)
            .map(|(handle, _)| handle.clone())
            .collect();
        for claim in expired {
            self.release_claim(&claim);
        }
    }
}

fn pid_from_pidfd(pidfd: &ReceivedFd) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.raw()))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Pid:")?.trim().parse().ok())
}

fn process_facts(pid: u32) -> Option<(u32, u64, char)> {
    let uid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })?;
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    let mut fields = stat[end + 1..].split_whitespace();
    let state = fields.next()?.chars().next()?;
    let start_time = fields.nth(18)?.parse().ok()?;
    Some((uid, start_time, state))
}

fn unified_cgroup(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
}

fn cgroup_contains(root: &str, process: &str) -> bool {
    root == "/"
        || process == root
        || process
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
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

    pub(crate) fn attach_project_process(
        &self,
        connection_id: u64,
        context: AttachmentHandle,
        pidfd: ReceivedFd,
    ) -> Result<()> {
        let sandbox = self
            .project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .adapter_sandbox(connection_id)
            .map(str::to_owned)
            .ok_or_else(|| {
                error(
                    ContextAdapterErrorCode::Unauthorized,
                    "connection is not a context adapter",
                )
            })?;
        let registration = self
            .sandbox_sessions
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&sandbox)
            .cloned()
            .ok_or_else(|| {
                error(
                    ContextAdapterErrorCode::InvalidProcess,
                    "sandbox registration is unavailable",
                )
            })?;
        let pid = pid_from_pidfd(&pidfd).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::InvalidProcess,
                "descriptor is not a live pidfd",
            )
        })?;
        let (uid, start_time, state) = process_facts(pid).ok_or_else(|| {
            error(
                ContextAdapterErrorCode::InvalidProcess,
                "process identity is unavailable",
            )
        })?;
        if uid != registration.owner_uid {
            return Err(error(
                ContextAdapterErrorCode::InvalidProcess,
                "process has the wrong owner",
            ));
        }
        let process_cgroup = unified_cgroup(pid);
        let sandbox_cgroup = (registration.root_pid != 0)
            .then(|| unified_cgroup(registration.root_pid))
            .flatten();
        if !matches!((process_cgroup.as_deref(), sandbox_cgroup.as_deref()),
            (Some(process), Some(root)) if cgroup_contains(root, process))
        {
            return Err(error(
                ContextAdapterErrorCode::InvalidProcess,
                "process is outside the managed sandbox cgroup",
            ));
        }
        let process = ProcessIdentity::new(pid, uid, start_time).map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidProcess,
                "process identity is invalid",
            )
        })?;
        let (already_attached, shared_leaf) = self
            .project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .prepare_process_attachment(connection_id, process, &context, Instant::now())?;
        if already_attached {
            return Ok(());
        }
        if !matches!(state, 'T' | 't') {
            return Err(error(
                ContextAdapterErrorCode::InvalidProcess,
                "process is not stopped",
            ));
        }
        let root = sandbox_cgroup.expect("validated sandbox cgroup");
        let provisional_leaf = shared_leaf.is_none();
        let leaf = shared_leaf.unwrap_or_else(|| {
            let name = format!("agent-sandbox-context/{}", uuid::Uuid::new_v4());
            Path::new("/sys/fs/cgroup")
                .join(root.trim_start_matches('/'))
                .join(name)
        });
        let leaf_cgroup = format!(
            "/{}",
            leaf.strip_prefix("/sys/fs/cgroup")
                .expect("controlled cgroup is under cgroupfs")
                .display()
        );
        std::fs::create_dir_all(&leaf).map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidProcess,
                "controlled process cgroup cannot be created",
            )
        })?;
        std::fs::write(leaf.join("cgroup.procs"), pid.to_string()).map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidProcess,
                "process cannot be moved into the controlled cgroup",
            )
        })?;

        // Once cgroup.procs accepts the PID, every return path must either
        // complete the attachment or kill the still-stopped process and clean
        // up both provisional registry state and a newly-created leaf.
        let rollback = AttachmentFailureGuard::new(
            &self.project_context,
            process,
            pidfd,
            provisional_leaf.then(|| leaf.clone()),
        );
        if unified_cgroup(pid).as_deref() != Some(leaf_cgroup.as_str()) {
            return Err(error(
                ContextAdapterErrorCode::InvalidProcess,
                "controlled cgroup membership could not be verified",
            ));
        }
        let registry_pidfd = rollback.pidfd.try_clone().map_err(|_| {
            error(
                ContextAdapterErrorCode::InvalidProcess,
                "pidfd could not be retained for attachment",
            )
        })?;
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .attach_process(
                connection_id,
                process,
                context,
                registry_pidfd,
                Some(leaf),
                Instant::now(),
            )?;
        if agent_sandbox_sysutil::pidfd_send_signal(rollback.pidfd.raw(), nix::libc::SIGCONT)
            .is_err()
        {
            return Err(error(
                ContextAdapterErrorCode::InvalidProcess,
                "attached process could not be resumed",
            ));
        }
        rollback.commit();
        Ok(())
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

    pub(crate) fn resolve_attached_process(
        &self,
        process: &ProcessIdentity,
        cgroup: CgroupIdentity,
        connection_id: u64,
    ) -> Option<ResolvedWorkspace> {
        self.project_context
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve_attached_process(process, cgroup, connection_id, Instant::now())
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
    fn cgroup_containment_respects_component_boundaries() {
        assert!(cgroup_contains("/", "/sandbox/child"));
        assert!(cgroup_contains("/sandbox", "/sandbox/child"));
        assert!(!cgroup_contains("/sandbox", "/sandbox-escape"));
    }

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

    #[test]
    fn replaced_workspace_invalidates_new_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workspace");
        std::fs::create_dir(&root).unwrap();
        let owner = root.metadata().unwrap().uid();
        let mut registry = ProjectContextRegistry::default();
        let activation = registry.activate("sandbox", owner, &root).unwrap();
        registry.register_adapter(7, "sandbox").unwrap();
        let binding = registry
            .bind_session(
                7,
                ExternalSessionKey::new("session").unwrap(),
                activation.activation,
            )
            .unwrap();

        std::fs::rename(&root, dir.path().join("moved")).unwrap();
        std::fs::create_dir(&root).unwrap();

        assert!(registry.resolve_binding(7, &binding).is_none());
    }

    #[test]
    fn attached_claim_stays_live_until_release() {
        use std::os::fd::IntoRawFd;

        let dir = tempfile::tempdir().unwrap();
        let owner = dir.path().metadata().unwrap().uid();
        let mut registry = ProjectContextRegistry::default();
        let activation = registry.activate("sandbox", owner, dir.path()).unwrap();
        registry.register_adapter(7, "sandbox").unwrap();
        let binding = registry
            .bind_session(
                7,
                ExternalSessionKey::new("session").unwrap(),
                activation.activation.clone(),
            )
            .unwrap();
        let now = Instant::now();
        let claim = registry
            .begin_operation(
                7,
                ExternalOperationKey::new("operation").unwrap(),
                binding,
                activation.activation,
                now,
            )
            .unwrap();
        let process = ProcessIdentity::new(123, owner, 456).unwrap();
        let fd = File::open("/dev/null").unwrap().into_raw_fd();
        let leaf = dir.path().join("context-leaf");
        std::fs::create_dir(&leaf).unwrap();
        let context = AttachmentHandle::Claim(claim.clone());
        registry
            .attach_process(
                7,
                process,
                context.clone(),
                ReceivedFd::new(fd),
                Some(leaf.clone()),
                now,
            )
            .unwrap();
        let cgroup = CgroupIdentity::new(leaf.metadata().unwrap().ino()).unwrap();
        assert_eq!(
            registry.attached_cgroup_for_process(&process, 7),
            Some(cgroup)
        );
        assert!(
            registry
                .resolve_attached_process(&process, cgroup, 7, now)
                .is_some()
        );
        assert!(
            registry
                .resolve_attached_process(&process, cgroup, 8, now)
                .is_none()
        );
        assert!(
            registry
                .resolve_attached_process(&process, CgroupIdentity::new(999).unwrap(), 7, now)
                .is_none()
        );
        assert_eq!(
            registry
                .prepare_process_attachment(7, process, &context, now)
                .unwrap(),
            (true, Some(leaf.clone()))
        );
        assert_eq!(
            registry
                .prepare_process_attachment(
                    7,
                    ProcessIdentity::new(124, owner, 457).unwrap(),
                    &context,
                    now,
                )
                .unwrap_err()
                .code,
            ContextAdapterErrorCode::Conflict
        );

        assert!(
            registry
                .resolve_claim(7, &claim, now + CLAIM_TTL + Duration::from_secs(1))
                .is_some()
        );
        registry.release_claim_for(7, &claim).unwrap();
        assert!(registry.attachments.is_empty());
        assert!(!leaf.exists());
    }

    #[test]
    fn failed_attachment_rolls_back_registry_and_provisional_leaf() {
        use std::os::fd::IntoRawFd;

        let dir = tempfile::tempdir().unwrap();
        let owner = dir.path().metadata().unwrap().uid();
        let mut registry = ProjectContextRegistry::default();
        let activation = registry.activate("sandbox", owner, dir.path()).unwrap();
        registry.register_adapter(7, "sandbox").unwrap();
        let binding = registry
            .bind_session(
                7,
                ExternalSessionKey::new("session").unwrap(),
                activation.activation.clone(),
            )
            .unwrap();
        let claim = registry
            .begin_operation(
                7,
                ExternalOperationKey::new("operation").unwrap(),
                binding,
                activation.activation,
                Instant::now(),
            )
            .unwrap();
        let process = ProcessIdentity::new(123, owner, 456).unwrap();
        let leaf = dir.path().join("provisional-leaf");
        std::fs::create_dir(&leaf).unwrap();
        registry
            .attach_process(
                7,
                process,
                AttachmentHandle::Claim(claim),
                ReceivedFd::new(File::open("/dev/null").unwrap().into_raw_fd()),
                Some(leaf.clone()),
                Instant::now(),
            )
            .unwrap();

        let registry = Mutex::new(registry);
        let rollback = AttachmentFailureGuard::new(
            &registry,
            process,
            ReceivedFd::new(File::open("/dev/null").unwrap().into_raw_fd()),
            Some(leaf.clone()),
        );
        drop(rollback);

        let registry = registry.lock().unwrap();
        assert!(registry.attachments.is_empty());
        assert!(!leaf.exists());
    }
}
