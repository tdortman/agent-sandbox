//! The kernel side of a mount: the new mount API and `/proc` text formats.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd},
};

use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, fsconfig_create, fsconfig_set_flag,
    fsconfig_set_string, fsmount, fsopen, move_mount,
};

use crate::options::{AtimeMode, MountParams};

/// Create a `fuse` filesystem on `dev_fuse` and attach it to `target`.
///
/// `nosuid` and `nodev` are always set. `uid` and `gid` become the kernel's
/// `user_id` and `group_id`, the only identity allowed to use the mount
/// without `allow_other`.
///
/// # Errors
/// Returns the first failing syscall's error.
pub fn mount_fuse(
    dev_fuse: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    params: &MountParams,
    rootmode: u32,
    uid: u32,
    gid: u32,
) -> io::Result<()> {
    let fs = fsopen("fuse", FsOpenFlags::FSOPEN_CLOEXEC)?;

    fsconfig_set_string(
        &fs,
        "source",
        params.fsname.as_deref().unwrap_or("/dev/fuse"),
    )?;

    if let Some(subtype) = &params.subtype {
        fsconfig_set_string(&fs, "subtype", subtype.as_str())?;
    }

    fsconfig_set_string(&fs, "fd", dev_fuse.as_raw_fd().to_string())?;
    fsconfig_set_string(&fs, "rootmode", format!("{rootmode:o}"))?;
    fsconfig_set_string(&fs, "user_id", uid.to_string())?;
    fsconfig_set_string(&fs, "group_id", gid.to_string())?;

    for (enabled, flag) in [
        (params.default_permissions, "default_permissions"),
        (params.allow_other, "allow_other"),
        (params.read_only, "ro"),
        (params.sync, "sync"),
        (params.dirsync, "dirsync"),
    ] {
        if enabled {
            fsconfig_set_flag(&fs, flag)?;
        }
    }

    for (value, key) in [(params.max_read, "max_read"), (params.blksize, "blksize")] {
        if let Some(value) = value {
            fsconfig_set_string(&fs, key, value.to_string())?;
        }
    }

    fsconfig_create(&fs)?;

    let mount = fsmount(&fs, FsMountFlags::FSMOUNT_CLOEXEC, attribute_flags(params))?;

    move_mount(
        &mount,
        "",
        target,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )?;

    Ok(())
}

/// Per-mount attributes: the forced `nosuid,nodev` plus the requested ones.
fn attribute_flags(params: &MountParams) -> MountAttrFlags {
    let mut flags = MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NODEV;

    flags.set(MountAttrFlags::MOUNT_ATTR_RDONLY, params.read_only);
    flags.set(MountAttrFlags::MOUNT_ATTR_NOEXEC, params.noexec);
    flags.set(MountAttrFlags::MOUNT_ATTR_NODIRATIME, params.nodiratime);
    flags.set(MountAttrFlags::MOUNT_ATTR_NOSYMFOLLOW, params.nosymfollow);

    match params.atime {
        AtimeMode::Relatime => {}
        AtimeMode::Noatime => flags |= MountAttrFlags::MOUNT_ATTR_NOATIME,
        AtimeMode::Strictatime => flags |= MountAttrFlags::MOUNT_ATTR_STRICTATIME,
    }

    flags
}

/// One line of `/proc/<pid>/mountinfo`.
#[derive(Debug, PartialEq, Eq)]
pub struct MountInfo {
    /// The mount id.
    pub id: u64,

    /// The mounted subtree of the filesystem.
    pub root: String,

    /// Propagation fields such as `shared:3`.
    pub optional: Vec<String>,

    /// The filesystem type.
    pub fstype: String,

    /// Superblock options.
    pub super_options: String,
}

impl MountInfo {
    /// Whether the mount is a FUSE filesystem mounted as `fuse`.
    #[must_use]
    pub fn is_fuse(&self) -> bool {
        self.fstype == "fuse" || self.fstype.starts_with("fuse.")
    }

    /// Whether the kernel recorded `uid` as the mount's owner.
    #[must_use]
    pub fn owned_by(&self, uid: u32) -> bool {
        let wanted = format!("user_id={uid}");

        self.super_options.split(',').any(|option| option == wanted)
    }

    /// Whether mounts below this one propagate to its peers, which may sit in
    /// another mount namespace. A slave (`master:`) only receives.
    #[must_use]
    pub fn propagates(&self) -> bool {
        self.optional
            .iter()
            .any(|field| field.starts_with("shared:"))
    }
}

/// The mount with `id` in a `mountinfo` listing.
#[must_use]
pub fn find_mount(mountinfo: &str, id: u64) -> Option<MountInfo> {
    mountinfo
        .lines()
        .filter_map(parse_mountinfo_line)
        .find(|mount| mount.id == id)
}

fn parse_mountinfo_line(line: &str) -> Option<MountInfo> {
    let fields: Vec<&str> = line.split(' ').collect();
    let separator = fields.iter().position(|field| *field == "-")?;

    Some(MountInfo {
        id: fields.first()?.parse().ok()?,
        root: (*fields.get(3)?).to_owned(),
        optional: fields
            .get(6..separator)?
            .iter()
            .map(|f| (*f).to_owned())
            .collect(),
        fstype: (*fields.get(separator + 1)?).to_owned(),
        super_options: (*fields.get(separator + 3)?).to_owned(),
    })
}

/// The `mnt_id` line of a `/proc/<pid>/fdinfo/<fd>` file.
#[must_use]
pub fn mount_id_from_fdinfo(fdinfo: &str) -> Option<u64> {
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))?
        .trim()
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::{find_mount, mount_id_from_fdinfo};

    const MOUNTINFO: &str = "\
22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw
901 22 0:77 / /home/u/mnt rw,nosuid,nodev,relatime - fuse.ovnfs ovnfs \
                             rw,user_id=1000,group_id=100,default_permissions
902 22 0:78 / /home/u/other rw,relatime master:3 shared:7 - fuse other rw,user_id=1001,group_id=100
903 22 0:79 / /home/u/slave rw,relatime master:3 - fuse other rw,user_id=1000,group_id=100
";

    #[test]
    fn fuse_mount_is_found_with_its_owner() {
        let mount = find_mount(MOUNTINFO, 901).expect("mount 901");

        assert!(mount.is_fuse());
        assert!(mount.owned_by(1000));
        assert!(!mount.owned_by(1001));
        assert!(!mount.propagates());
        assert_eq!(mount.root, "/");
    }

    #[test]
    fn propagation_fields_are_reported() {
        assert!(find_mount(MOUNTINFO, 902).expect("mount 902").propagates());
        assert!(find_mount(MOUNTINFO, 22).expect("mount 22").propagates());
        assert!(!find_mount(MOUNTINFO, 22).expect("mount 22").is_fuse());
        assert!(!find_mount(MOUNTINFO, 903).expect("mount 903").propagates());
        assert!(find_mount(MOUNTINFO, 5).is_none());
    }

    #[test]
    fn fdinfo_mount_id_is_read() {
        let fdinfo = "pos:\t0\nflags:\t010000000\nmnt_id:\t901\nino:\t2\n";

        assert_eq!(mount_id_from_fdinfo(fdinfo), Some(901));
        assert_eq!(mount_id_from_fdinfo("pos:\t0\n"), None);
    }
}
