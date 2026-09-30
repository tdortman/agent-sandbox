//! Filesystem policy expansion against live paths, symlinks and procfs handles.

use std::{
    ffi::OsStr,
    fs::{self, File},
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::PathBuf,
};

use agent_sandbox_core::expand_policy_path;

#[test]
fn policy_paths_follow_live_aliases_and_preserve_unresolvable_paths() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let root = temporary.path();
    let first = root.join("first");
    let second = root.join("second");
    fs::create_dir_all(first.join("sub")).expect("first directory");
    fs::create_dir_all(second.join("sub")).expect("second directory");
    let file = first.join("sub/file");
    fs::write(&file, "first").expect("first file");
    fs::write(second.join("sub/file"), "second").expect("second file");
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&first, &alias).expect("directory alias");
    std::os::unix::fs::symlink("alias/sub/file", root.join("chain")).expect("chained alias");
    std::os::unix::fs::symlink("missing", root.join("dangling")).expect("dangling alias");
    std::os::unix::fs::symlink("loop", root.join("loop")).expect("symlink loop");
    let non_utf8 = first.join(OsStr::from_bytes(b"file-\xff"));
    fs::write(&non_utf8, "present").expect("non-UTF-8 filename");
    let open_file = File::open(&file).expect("open file");
    let proc_path = PathBuf::from(format!("/proc/self/fd/{}", open_file.as_raw_fd()));

    for path in [
        file.clone(),
        PathBuf::from("/"),
        first.join("missing"),
        first.join("sub/file/child"),
        first.join("sub/file/"),
        first.join("sub/"),
        first.join("./sub/file"),
        first.join("sub//file"),
        alias.join("sub/file"),
        alias.join("../first/sub/file"),
        root.join("chain"),
        root.join("dangling"),
        root.join("loop"),
        alias.join("missing"),
        non_utf8,
        proc_path.clone(),
    ] {
        let expected = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
        assert_eq!(expand_policy_path(&path, None, None), expected, "{path:?}");
    }

    assert_eq!(expand_policy_path(&root.join("chain"), None, None), file);
    fs::remove_file(&alias).expect("remove alias");
    std::os::unix::fs::symlink(&second, &alias).expect("retarget alias");
    assert_eq!(
        expand_policy_path(&root.join("chain"), None, None),
        second.join("sub/file")
    );
    fs::remove_file(&file).expect("unlink held file");
    assert_eq!(expand_policy_path(&proc_path, None, None), proc_path);
}
