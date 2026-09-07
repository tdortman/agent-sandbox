//! Held policy paths for the epoch observer. No path canonicalization: both
//! sides of every symlink and each directory entry must remain observable.
use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

use nix::{
    fcntl::{OFlag, OpenHow, ResolveFlag, openat, openat2, readlinkat},
    sys::{stat::Mode, statfs::fstatfs},
};

pub(super) struct Entry {
    pub directory: PathBuf,
    pub name: OsString,
    pub file: File,
}

struct Link {
    path: PathBuf,
    target: OsString,
    file: File,
}

pub(super) struct SourcePath {
    pub original: PathBuf,
    pub resolved: PathBuf,
    pub entries: Vec<Entry>,
    links: Vec<Link>,
}

impl SourcePath {
    pub fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "policy path must be absolute without parent traversal",
            ));
        }
        let mut pending: VecDeque<_> = path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .skip(1)
            .map(|s| OsString::from_vec(s.to_vec()))
            .collect();
        let mut directory = PathBuf::from("/");
        let mut entries = Vec::new();
        let mut links = Vec::new();
        while let Some(name) = pending.pop_front() {
            if name.is_empty() {
                continue;
            }
            if entries.len() == 64 || name.as_bytes().len() > 255 {
                return Err(io::Error::other("policy path exceeds observer capacity"));
            }
            let file = open_directory(&directory)?;
            entries.push(Entry {
                directory: directory.clone(),
                name: name.clone(),
                file,
            });
            let entry = entries
                .last()
                .ok_or_else(|| io::Error::other("missing path entry"))?;
            if name == "." {
                continue;
            }
            if name == ".." {
                directory.pop();
                continue;
            }
            let child = directory.join(&name);
            let fd = match openat(
                &entry.file,
                name.as_os_str(),
                OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(nix::errno::Errno::ENOENT) if pending.is_empty() => {
                    directory = child;
                    break;
                }
                Err(error) => return Err(error.into()),
            };
            let file = File::from(fd);
            if !file.metadata()?.file_type().is_symlink() {
                directory = child;
                continue;
            }
            if links.len() == 40 {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            // Ordinary local symlinks have immutable targets. Procfs magic
            // links and filesystems without that contract cannot grant access.
            if !matches!(
                fstatfs(&file)?.filesystem_type().0,
                0x9123_683E | 0xEF53 | 0x0102_1994 | 0x5846_5342 | 0x7371_7368 | 0xE0F5_E1E2
            ) {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            let target = readlinkat(&file, "")?;
            if target.as_bytes().starts_with(b"/") {
                directory = PathBuf::from("/");
            }
            for component in target.as_bytes().split(|b| *b == b'/').rev() {
                pending.push_front(OsString::from_vec(component.to_vec()));
            }
            links.push(Link {
                path: child,
                target,
                file,
            });
        }
        Ok(Self {
            original: path.to_owned(),
            resolved: directory,
            entries,
            links,
        })
    }

    pub fn verify_root(&self, root: &File) -> io::Result<()> {
        let compare = |path: &Path, expected: &File| -> io::Result<()> {
            let actual = open_in_root(root, path)?;
            let actual = actual.metadata()?;
            let expected = expected.metadata()?;
            if (actual.dev(), actual.ino()) != (expected.dev(), expected.ino()) {
                return Err(io::Error::other("resolver source path differs"));
            }
            Ok(())
        };
        // Matching leaves alone misses independently replaceable aliases.
        for entry in &self.entries {
            compare(&entry.directory, &entry.file)?;
        }
        for link in &self.links {
            compare(&link.path, &link.file)?;
        }
        let expected = self.open_watch(true)?;
        match expected {
            Some(file) => compare(&self.resolved, &file),
            None => match open_in_root(root, &self.resolved) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
                Ok(_) => Err(io::Error::other("resolver has an unobserved source")),
            },
        }
    }

    pub fn links(&self) -> impl Iterator<Item = &File> {
        self.links.iter().map(|link| &link.file)
    }

    pub fn recheck_links(&self) -> io::Result<()> {
        for link in &self.links {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&link.path)?;
            let before = link.file.metadata()?;
            let after = file.metadata()?;
            let target = readlinkat(&file, "")?;
            if !after.file_type().is_symlink()
                || before.dev() != after.dev()
                || before.ino() != after.ino()
                || target != link.target
            {
                return Err(io::Error::other(
                    "policy symlink changed during observation",
                ));
            }
        }
        Ok(())
    }

    pub fn open_source(&self, recheck: bool) -> io::Result<Option<File>> {
        self.open_entry(recheck, false)
    }

    pub fn open_watch(&self, recheck: bool) -> io::Result<Option<File>> {
        self.open_entry(recheck, true)
    }

    fn open_entry(&self, recheck: bool, watch_only: bool) -> io::Result<Option<File>> {
        let path = if recheck {
            &self.original
        } else {
            &self.resolved
        };
        let nofollow = if recheck && !self.links.is_empty() {
            0
        } else {
            libc::O_NOFOLLOW
        };
        let access = if watch_only { libc::O_PATH } else { 0 };
        match OpenOptions::new()
            .read(true)
            .custom_flags(access | nofollow | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => {
                let kind = file.metadata()?.file_type();
                if kind.is_file() || (watch_only && !kind.is_symlink()) {
                    Ok(Some(file))
                } else {
                    Err(io::Error::other("unexpected policy source type"))
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

fn open_in_root(root: &File, path: &Path) -> io::Result<File> {
    Ok(File::from(openat2(
        root,
        path,
        OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS),
    )?))
}

pub(super) fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

pub(super) fn entry_name(name: &OsStr) -> io::Result<[u8; 256]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 || bytes.contains(&0) || bytes.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid watched entry name",
        ));
    }
    let mut value = [0; 256];
    value[..bytes.len()].copy_from_slice(bytes);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    #[ignore = "requires root and the host NSS daemon at /run/nscd/socket"]
    fn host_nss_sources_share_observer_graph() {
        use nix::sys::socket::{getsockopt, sockopt};
        let peer = std::os::unix::net::UnixStream::connect("/run/nscd/socket").unwrap();
        let credentials = getsockopt(&peer, sockopt::PeerCredentials).unwrap();
        let root = File::open(format!("/proc/{}/root", credentials.pid())).unwrap();
        for name in ["/etc/passwd", "/etc/nsswitch.conf"] {
            SourcePath::open(Path::new(name))
                .unwrap()
                .verify_root(&root)
                .unwrap();
            println!("verified NSS peer {} source {name}", credentials.pid());
        }
    }

    #[test]
    #[ignore = "requires root and private mount namespaces"]
    fn resolver_alias_with_same_leaf_but_different_parent_is_rejected() {
        use std::{
            io::{BufRead, BufReader, Write},
            process::{Command, Stdio},
        };

        assert!(nix::unistd::Uid::effective().is_root());
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let alias = temp.path().join("alias");
        std::fs::create_dir(&original).unwrap();
        std::fs::create_dir(&alias).unwrap();
        let path = original.join("passwd");
        std::fs::write(&path, "fixture:x:1000:100::/home/fixture:/bin/sh\n").unwrap();
        std::fs::hard_link(&path, alias.join("passwd")).unwrap();
        let source = SourcePath::open(&path).unwrap();
        let mut peer = Command::new("unshare")
            .args([
                "--mount",
                "--propagation",
                "private",
                "sh",
                "-c",
                r#"mount --bind "$1" "$2" || exit; echo ready; read finish"#,
                "sh",
            ])
            .arg(&alias)
            .arg(&original)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(peer.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        let root = File::open(format!("/proc/{}/root", peer.id())).unwrap();
        let local = std::fs::metadata(&path).unwrap();
        let remote = open_in_root(&root, &path).unwrap().metadata().unwrap();
        assert_eq!((local.dev(), local.ino()), (remote.dev(), remote.ino()));
        assert!(
            source.verify_root(&root).is_err(),
            "same leaf must not hide an independent parent"
        );
        writeln!(peer.stdin.take().unwrap(), "finish").unwrap();
        assert!(peer.wait().unwrap().success());
    }

    #[test]
    fn resolver_view_requires_the_same_graph_and_confines_absolute_links() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("policy");
        std::fs::write(&target, "{}").unwrap();
        let alias = temp.path().join("alias");
        symlink(&target, &alias).unwrap();
        let source = SourcePath::open(&alias).unwrap();
        source.verify_root(&File::open("/").unwrap()).unwrap();
        let different = File::open(temp.path()).unwrap();
        assert!(source.verify_root(&different).is_err());
        // The absolute target exists on the host but not in this root.
        let nested = temp.path().join("directory");
        std::fs::create_dir(&nested).unwrap();
        symlink(temp.path(), nested.join("escape")).unwrap();
        assert!(open_in_root(&different, Path::new("/directory/escape/policy")).is_err());
    }

    #[test]
    fn sockets_can_be_watched_but_never_read_as_policy_documents() {
        use std::os::unix::{fs::FileTypeExt, net::UnixListener};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nss.sock");
        let listener = UnixListener::bind(&path).expect("socket");
        let source = SourcePath::open(&path).expect("source path");
        for recheck in [false, true] {
            assert!(source.open_source(recheck).is_err());
            let file = source
                .open_watch(recheck)
                .expect("watch")
                .expect("present socket");
            assert!(file.metadata().expect("metadata").file_type().is_socket());
        }
        drop(listener);
        std::fs::remove_file(&path).expect("remove socket");
        symlink("elsewhere", &path).expect("replace with unobserved symlink");
        for recheck in [false, true] {
            assert!(source.open_watch(recheck).is_err());
        }
    }

    #[test]
    fn observes_both_sides_of_links_and_refuses_changed_or_unsupported_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("actual")).unwrap();
        std::fs::write(root.join("actual/policy"), "{}").unwrap();
        symlink("actual", root.join("alias")).unwrap();
        let path = SourcePath::open(&root.join("alias/policy")).unwrap();
        assert_eq!(path.resolved, root.join("actual/policy"));
        assert!(path.entries.iter().any(|e| e.name == "alias"));
        assert!(path.entries.iter().any(|e| e.name == "actual"));
        assert!(path.open_source(false).unwrap().is_some());
        path.recheck_links().unwrap();
        std::fs::remove_file(root.join("alias")).unwrap();
        symlink("actual", root.join("alias")).unwrap();
        assert!(path.recheck_links().is_err());
        let missing = SourcePath::open(&root.join("alias/missing")).unwrap();
        assert!(missing.open_source(false).unwrap().is_none());
        std::fs::write(root.join("actual/missing"), "{}").unwrap();
        assert!(missing.open_source(true).unwrap().is_some());
        symlink("../actual/./policy", root.join("actual/relative")).unwrap();
        let relative = SourcePath::open(&root.join("actual/relative")).unwrap();
        assert_eq!(relative.resolved, root.join("actual/policy"));
        relative.recheck_links().unwrap();
        symlink(root.join("actual/policy"), root.join("absolute")).unwrap();
        assert_eq!(
            SourcePath::open(&root.join("absolute")).unwrap().resolved,
            root.join("actual/policy")
        );
        nix::unistd::mkfifo(&root.join("fifo"), Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
        assert!(
            SourcePath::open(&root.join("fifo"))
                .unwrap()
                .open_source(false)
                .is_err()
        );
        symlink("loop", root.join("loop")).unwrap();
        assert!(SourcePath::open(&root.join("loop")).is_err());
        assert!(SourcePath::open(Path::new("relative")).is_err());
        assert!(SourcePath::open(&root.join("../policy")).is_err());
        assert!(SourcePath::open(&root.join("absent/policy")).is_err());
        assert!(SourcePath::open(Path::new("/proc/self/fd/0")).is_err());
        assert!(entry_name(OsStr::new("a/b")).is_err());
    }
}
