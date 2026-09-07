//! Native caller for the one-shot policy epoch programs.
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    os::fd::{AsFd, AsRawFd},
    path::Path,
};

use aya::{
    maps::{Array, Map, MapData, MapType},
    programs::{ProgramFd, ProgramInfo},
};

use super::source::{SourcePath, entry_name, open_directory};

type Bytes<const N: usize> = Array<MapData, [u8; N]>;

/// Held source and directory descriptors for one unpublished network snapshot.
///
/// Construct only from trusted private program pins with the epoch LSM hooks
/// already attached. The observer must share the publisher's mount namespace.
/// Callers still establish policy-source authority, runtime eligibility, and
/// the mount-isolation contract before installing or publishing any grant.
pub struct ObservedNetworkSources {
    /// Documents in the caller's source order. A missing leaf is `None`.
    pub documents: Vec<Option<String>>,
    programs: BTreeMap<&'static str, ProgramFd>,
    identities: Bytes<56>,
    watch: Bytes<64>,
    paths: Vec<SourcePath>,
    held: Vec<File>,
    primary: [u8; 32],
    _mount_namespace: File,
}

impl ObservedNetworkSources {
    /// Observe an existing primary policy and optional additional source files.
    ///
    /// Paths must include logical symlink paths and all candidate layers, even
    /// layers that policy selection currently rejects. Returned bytes do not
    /// establish authority or project containment on their own.
    ///
    /// # Errors
    /// Refuses incompatible or reused maps, missing intermediate directories,
    /// unsupported symlinks, nonregular sources, capacity exhaustion, busy or
    /// changed paths, and documents larger than one MiB or invalid UTF-8.
    pub fn capture(pins: &Path, cgroup: u64, sources: &[&Path]) -> io::Result<Self> {
        Self::capture_with_watches(pins, cgroup, sources, &[])
    }

    /// Observe policy documents plus paths whose identities alone matter,
    /// such as the NSS server socket. Watch-only paths append no documents.
    ///
    /// # Errors
    /// Has the same freshness and capacity requirements as [`Self::capture`].
    /// Watch-only leaves may be nonregular files; policy documents must remain
    /// regular files even when a watch-only path also names them.
    pub fn capture_with_watches(
        pins: &Path,
        cgroup: u64,
        sources: &[&Path],
        watch_only: &[&Path],
    ) -> io::Result<Self> {
        if cgroup == 0
            || sources.is_empty()
            || sources.len() > 64
            || watch_only.len() > 64 - sources.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid source observation request",
            ));
        }
        let mut programs = BTreeMap::new();
        let mut maps = BTreeMap::new();
        for name in [
            "init_mount_scope",
            "init_identities",
            "watch_source",
            "watch_ancestor",
            "publish_watch",
        ] {
            let info = ProgramInfo::from_pin(pins.join(name)).map_err(io::Error::other)?;
            if info.program_type() as u32 != 31
                || info.name() != &name.as_bytes()[..name.len().min(15)]
            {
                return Err(io::Error::other("invalid epoch syscall program"));
            }
            for id in info
                .map_ids()
                .map_err(io::Error::other)?
                .unwrap_or_default()
            {
                let data = MapData::from_id(id).map_err(io::Error::other)?;
                let info = data.info().map_err(io::Error::other)?;
                let name = info.name().to_vec();
                if maps.get(&name).is_some_and(|previous| *previous != id) {
                    return Err(io::Error::other("epoch programs do not share maps"));
                }
                maps.insert(name, id);
            }
            programs.insert(name, info.fd().map_err(io::Error::other)?);
        }
        let identities = array(&maps, b"identities")?;
        let watch = array::<64>(&maps, b"watch")?;
        let mount = array::<24>(&maps, b"mount_scope")?;
        if watch.get(&0, 0).map_err(io::Error::other)? != [0; 64]
            || mount.get(&0, 0).map_err(io::Error::other)? != [0; 24]
        {
            return Err(io::Error::other("epoch observation is not fresh"));
        }
        let mut names = array::<256>(&maps, b"watch_name")?;
        // Hold the namespace before the first path resolution. The kernel
        // compares both its identity and mount-event sequence at publication.
        let mount_namespace = File::open("/proc/self/ns/mnt")?;
        invoke(&programs, "init_mount_scope")?;
        let paths = sources
            .iter()
            .chain(watch_only.iter())
            .map(|path| SourcePath::open(path))
            .collect::<io::Result<Vec<_>>>()?;
        let primary = paths[0]
            .open_source(false)?
            .ok_or_else(|| io::Error::other("missing primary policy"))?;
        let parent = open_directory(
            paths[0]
                .resolved
                .parent()
                .ok_or_else(|| io::Error::other("missing primary parent"))?,
        )?;
        let mut observer = Self {
            documents: Vec::new(),
            programs,
            identities,
            watch,
            paths,
            held: vec![primary, parent],
            primary: [0; 32],
            _mount_namespace: mount_namespace,
        };
        let identity = observer.query(
            "init_identities",
            Some(observer.held[0].as_raw_fd()),
            observer.held[1].as_raw_fd(),
        )?;
        if identity[40..] != [0; 16] {
            return Err(io::Error::other("primary source is busy"));
        }
        observer.primary.copy_from_slice(&identity[8..40]);
        let mut state = [0; 64];
        state[..32].copy_from_slice(&observer.primary);
        state[40..48].copy_from_slice(&cgroup.to_ne_bytes());
        observer.watch.set(0, state, 0).map_err(io::Error::other)?;
        let mut source_identities = Vec::new();
        let mut directory_identities = Vec::new();
        for index in 0..observer.paths.len() {
            let source = if index < sources.len() {
                observer.paths[index].open_source(false)?
            } else {
                observer.paths[index].open_watch(false)?
            };
            let identity = if let Some(file) = source {
                let identity = observer.query(
                    "watch_source",
                    Some(file.as_raw_fd()),
                    observer.held[1].as_raw_fd(),
                )?;
                observer.held.push(file);
                Some(identity[8..24].to_vec())
            } else {
                None
            };
            source_identities.push(identity);
            let links: Vec<_> = observer.paths[index]
                .links()
                .map(AsRawFd::as_raw_fd)
                .collect();
            for fd in links {
                observer.query("watch_source", Some(fd), observer.held[1].as_raw_fd())?;
            }
            for entry_index in 0..observer.paths[index].entries.len() {
                let entry = &observer.paths[index].entries[entry_index];
                names
                    .set(0, entry_name(&entry.name)?, 0)
                    .map_err(io::Error::other)?;
                let fd = entry.file.as_raw_fd();
                let identity = observer.query("watch_ancestor", None, fd)?;
                directory_identities.push((index, entry_index, identity[24..40].to_vec()));
            }
        }
        for path in &observer.paths {
            path.recheck_links()?;
        }
        for (path, entry, expected) in directory_identities {
            let file = open_directory(&observer.paths[path].entries[entry].directory)?;
            let identity = observer.query("init_identities", None, file.as_raw_fd())?;
            if identity[24..40] != expected || identity[48..] != [0; 8] {
                return Err(io::Error::other("policy ancestor changed or is busy"));
            }
            observer.held.push(file);
        }
        for (index, expected) in source_identities.into_iter().enumerate() {
            let source = if index < sources.len() {
                observer.paths[index].open_source(true)?
            } else {
                observer.paths[index].open_watch(true)?
            };
            let document = match (source, expected) {
                (None, None) => None,
                (Some(mut file), Some(expected)) => {
                    let identity = observer.query(
                        "init_identities",
                        Some(file.as_raw_fd()),
                        observer.held[1].as_raw_fd(),
                    )?;
                    if identity[8..24] != expected || identity[40..48] != [0; 8] {
                        return Err(io::Error::other("policy source changed or is busy"));
                    }
                    if index >= sources.len() {
                        observer.held.push(file);
                        continue;
                    }
                    let mut bytes = Vec::new();
                    (&mut file).take((1 << 20) + 1).read_to_end(&mut bytes)?;
                    if bytes.len() > 1 << 20
                        || u64::try_from(bytes.len()).map_err(io::Error::other)?
                            != file.metadata()?.len()
                    {
                        return Err(io::Error::other("invalid policy document size"));
                    }
                    observer.held.push(file);
                    Some(String::from_utf8(bytes).map_err(io::Error::other)?)
                }
                _ => return Err(io::Error::other("policy source presence changed")),
            };
            if index < sources.len() {
                observer.documents.push(document);
            }
        }
        observer.check_epoch()?;
        Ok(observer)
    }

    /// Resolved path held by this observation, in the input source order.
    /// Use this path for containment checks instead of resolving the source
    /// again.
    #[must_use]
    pub fn resolved_path(&self, index: usize) -> Option<&Path> {
        self.paths.get(index).map(|path| path.resolved.as_path())
    }

    /// Bind a resolver peer after its socket and NSS documents are observed.
    ///
    /// Verifies the passwd home, captures and freezes the transport's NSS map,
    /// and checks the resolver's directory and symlink graph. Callers must
    /// still attest the resolver implementation and its initial
    /// root/configuration.
    ///
    /// # Errors
    /// Refuses unobserved sockets, invalid documents, differing homes or source
    /// views, failed peer capture, and observations invalidated during capture.
    pub fn capture_nss_peer(
        &mut self,
        program: &Path,
        socket: &Path,
        documents: [usize; 2],
        uid: u32,
        home: &Path,
    ) -> io::Result<u32> {
        self.check_epoch()?;
        if !self.paths.iter().any(|path| path.original == socket) {
            return Err(io::Error::other("NSS socket was not observed"));
        }
        let document = |index: usize| {
            self.documents
                .get(index)
                .and_then(Option::as_deref)
                .ok_or_else(|| io::Error::other("missing observed NSS document"))
        };
        if super::file_passwd_home(document(documents[0])?, document(documents[1])?, uid)? != home {
            return Err(io::Error::other("NSS home differs from policy home"));
        }
        let peer = std::os::unix::net::UnixStream::connect(socket)?;
        let pid = super::capture_nss_peer(program, &peer)?;
        let root = File::open(format!("/proc/{pid}/root"))?;
        self.verify_source_root(&root, &documents)?;
        self.held.push(root);
        self.held.push(File::from(std::os::fd::OwnedFd::from(peer)));
        Ok(pid)
    }

    /// Verify that selected sources have the same directory and symlink graph
    /// under a held resolver root. Absolute links resolve within that root.
    ///
    /// Callers must bind this root to the captured resolver's lifetime and
    /// reject later root or mount changes before publishing grants.
    ///
    /// # Errors
    /// Refuses invalid indices, differing paths, and a changed observation.
    pub fn verify_source_root(&self, root: &File, indices: &[usize]) -> io::Result<()> {
        self.check_epoch()?;
        for &index in indices {
            self.paths
                .get(index)
                .ok_or_else(|| io::Error::other("invalid resolver source index"))?
                .verify_root(root)?;
        }
        self.check_epoch()
    }

    /// Publish the observed source epoch after the caller installs its grants.
    /// Keep this object alive for the grant's lifetime to retain inode
    /// references.
    ///
    /// # Errors
    /// Refuses a changed or already published epoch, busy source, or changed
    /// mount scope. Publication alone does not establish policy authority.
    pub fn publish(&mut self) -> io::Result<()> {
        self.check_epoch()?;
        let identity = self.query(
            "init_identities",
            Some(self.held[0].as_raw_fd()),
            self.held[1].as_raw_fd(),
        )?;
        if identity[8..40] != self.primary || identity[40..] != [0; 16] {
            return Err(io::Error::other("primary policy changed or is busy"));
        }
        invoke(&self.programs, "publish_watch")
    }

    fn check_epoch(&self) -> io::Result<()> {
        let state = self.watch.get(&0, 0).map_err(io::Error::other)?;
        if state[..32] != self.primary || state[32..40] != [0; 8] || state[48..] != [0; 16] {
            return Err(io::Error::other(
                "policy epoch changed or is already published",
            ));
        }
        Ok(())
    }

    fn query(&mut self, program: &str, source: Option<i32>, parent: i32) -> io::Result<[u8; 56]> {
        let mut query = [0; 56];
        query[..4].copy_from_slice(&source.unwrap_or(-1).to_ne_bytes());
        query[4..8].copy_from_slice(&parent.to_ne_bytes());
        self.identities.set(0, query, 0).map_err(io::Error::other)?;
        invoke(&self.programs, program)?;
        self.identities.get(&0, 0).map_err(io::Error::other)
    }
}

fn invoke(programs: &BTreeMap<&str, ProgramFd>, name: &str) -> io::Result<()> {
    let program = programs
        .get(name)
        .ok_or_else(|| io::Error::other("missing epoch program"))?;
    if agent_sandbox_sysutil::bpf_run_syscall_program(program.as_fd())? != 0 {
        return Err(io::Error::other(format!("kernel rejected {name}")));
    }
    Ok(())
}

fn array<const N: usize>(maps: &BTreeMap<Vec<u8>, u32>, name: &[u8]) -> io::Result<Bytes<N>>
where
    [u8; N]: aya::Pod,
{
    let id = maps
        .get(name)
        .ok_or_else(|| io::Error::other("missing epoch map"))?;
    let data = MapData::from_id(*id).map_err(io::Error::other)?;
    let info = data.info().map_err(io::Error::other)?;
    if info.map_type().map_err(io::Error::other)? != MapType::Array
        || info.key_size() != 4
        || usize::try_from(info.value_size()).map_err(io::Error::other)? != N
        || info.max_entries() != 1
    {
        return Err(io::Error::other("invalid epoch map layout"));
    }
    Array::try_from(Map::Array(data)).map_err(io::Error::other)
}
