//! The fusermount `-o` option string, reduced to what a sandbox may ask for.
//!
//! The kernel mount options `user_id`, `group_id`, `rootmode`, `fd`, `nosuid`
//! and `nodev` are never taken from the client: the helper derives them from
//! the verified requester and the mountpoint. Every other option is either on
//! the whitelist below or refused.

use thiserror::Error;

/// Longest `fsname` or `subtype` value accepted.
const MAX_NAME_LEN: usize = 255;

/// How the mount updates access times.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AtimeMode {
    /// The kernel default (`atime` and `relatime`).
    #[default]
    Relatime,

    /// `noatime`.
    Noatime,

    /// `strictatime`.
    Strictatime,
}

/// A validated mount request.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MountParams {
    /// `fsname=`: the mount source shown in `/proc/mounts`.
    pub fsname: Option<String>,

    /// `subtype=`: the suffix of the `fuse.` filesystem type.
    pub subtype: Option<String>,

    /// `ro`.
    pub read_only: bool,

    /// `noexec`.
    pub noexec: bool,

    /// `noatime`, `strictatime`.
    pub atime: AtimeMode,

    /// `nodiratime`.
    pub nodiratime: bool,

    /// `nosymfollow`.
    pub nosymfollow: bool,

    /// `sync`.
    pub sync: bool,

    /// `dirsync`.
    pub dirsync: bool,

    /// `default_permissions`.
    pub default_permissions: bool,

    /// `allow_other`; only parsed when the host permits it.
    pub allow_other: bool,

    /// `max_read=`.
    pub max_read: Option<u32>,

    /// `blksize=`.
    pub blksize: Option<u32>,

    /// `auto_unmount`: the shim unmounts when the client's socket closes.
    pub auto_unmount: bool,
}

/// Why an option string was refused.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum OptionError {
    /// The option is not on the whitelist.
    #[error("unknown option '{0}'")]
    Unknown(String),

    /// The option needs privilege the sandbox does not have.
    #[error("option '{0}' is not permitted in the agent sandbox")]
    Privileged(String),

    /// The option is known but its value is not acceptable.
    #[error("invalid value in option '{0}'")]
    Invalid(String),
}

/// Parse a fusermount `-o` string.
///
/// `allow_other_permitted` mirrors `user_allow_other` in `/etc/fuse.conf`.
///
/// # Errors
/// Returns the first option that is unknown, privileged or malformed.
pub fn parse_mount_options(
    raw: &str,
    allow_other_permitted: bool,
) -> Result<MountParams, OptionError> {
    let mut params = MountParams::default();

    for option in split_options(raw) {
        apply(&mut params, &option, allow_other_permitted)?;
    }

    Ok(params)
}

/// Split on commas. A backslash escapes the next character only inside
/// `fsname=` and `subtype=`, as fusermount does.
fn split_options(raw: &str) -> Vec<String> {
    let mut options = Vec::new();
    let mut current = String::new();
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        let escapable = current.starts_with("fsname=") || current.starts_with("subtype=");

        if c == '\\' && escapable && chars.peek().is_some() {
            current.push('\\');
            current.extend(chars.next());
        } else if c == ',' {
            options.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }

    options.push(current);
    options.retain(|option| !option.is_empty());
    options
}

fn apply(
    params: &mut MountParams,
    option: &str,
    allow_other_permitted: bool,
) -> Result<(), OptionError> {
    if let Some((key, value)) = option.split_once('=') {
        match key {
            "fsname" => params.fsname = Some(name_value(option, value)?),
            "subtype" => params.subtype = Some(name_value(option, value)?),
            "max_read" => params.max_read = Some(number(option, value)?),
            "blksize" => params.blksize = Some(number(option, value)?),
            // fusermount drops these: the kernel values come from the
            // requester.
            "fd" | "rootmode" | "user_id" | "group_id" => {}
            _ => return Err(OptionError::Unknown(option.into())),
        }

        return Ok(());
    }

    match option {
        "ro" => params.read_only = true,
        "rw" | "async" | "atime" | "relatime" | "diratime" | "norelatime" | "nostrictatime"
        | "symfollow" => {}
        "nosymfollow" => params.nosymfollow = true,
        "noexec" => params.noexec = true,
        "exec" => params.noexec = false,
        "noatime" => params.atime = AtimeMode::Noatime,
        "strictatime" => params.atime = AtimeMode::Strictatime,
        "nodiratime" => params.nodiratime = true,
        "sync" => params.sync = true,
        "dirsync" => params.dirsync = true,
        "default_permissions" => params.default_permissions = true,
        "auto_unmount" => params.auto_unmount = true,
        // Forced on every mount, so a client asking for them changes nothing.
        "nosuid" | "nodev" => {}
        // fusermount drops these: they have no effect on the mount.
        "nonempty" | "large_read" => {}
        "allow_other" if allow_other_permitted => params.allow_other = true,
        "allow_other" | "suid" | "dev" => return Err(OptionError::Privileged(option.into())),
        _ => return Err(OptionError::Unknown(option.into())),
    }

    Ok(())
}

fn number(option: &str, value: &str) -> Result<u32, OptionError> {
    value
        .parse()
        .map_err(|_| OptionError::Invalid(option.into()))
}

/// Unescape a `fsname=`/`subtype=` value and reject what a mount table cannot
/// carry.
fn name_value(option: &str, value: &str) -> Result<String, OptionError> {
    let mut name = String::new();
    let mut chars = value.chars();

    while let Some(c) = chars.next() {
        name.push(if c == '\\' {
            chars.next().unwrap_or(c)
        } else {
            c
        });
    }

    if name.is_empty() || name.len() > MAX_NAME_LEN || name.chars().any(char::is_control) {
        return Err(OptionError::Invalid(option.into()));
    }

    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::{AtimeMode, OptionError, parse_mount_options};

    #[test]
    fn go_fuse_option_set_is_accepted() {
        let params = parse_mount_options(
            "default_permissions,nodev,nosuid,noatime,fsname=ovnfs,subtype=ovnfs,max_read=131072",
            false,
        )
        .expect("ovnfs options parse");

        assert!(params.default_permissions);
        assert_eq!(params.atime, AtimeMode::Noatime);
        assert_eq!(params.fsname.as_deref(), Some("ovnfs"));
        assert_eq!(params.subtype.as_deref(), Some("ovnfs"));
        assert_eq!(params.max_read, Some(131_072));
    }

    #[test]
    fn libfuse_option_set_is_accepted() {
        let params = parse_mount_options(
            "rw,nosuid,nodev,norelatime,nosymfollow,fsname=/srv/data,subtype=bindfs,\
             default_permissions,auto_unmount",
            false,
        )
        .expect("libfuse options parse");

        assert_eq!(params.fsname.as_deref(), Some("/srv/data"));
        assert!(params.auto_unmount);
        assert!(params.nosymfollow);
    }

    #[test]
    fn client_cannot_choose_forced_kernel_options() {
        let params = parse_mount_options("user_id=0,group_id=0,rootmode=40000,fd=9", false)
            .expect("forced options are dropped");

        assert_eq!(params, super::MountParams::default());
    }

    #[test]
    fn privileged_and_unknown_options_are_refused() {
        for (raw, expected) in [
            ("allow_other", "allow_other"),
            ("suid", "suid"),
            ("dev", "dev"),
        ] {
            assert_eq!(
                parse_mount_options(raw, false),
                Err(OptionError::Privileged(expected.into())),
                "{raw}"
            );
        }

        for raw in ["allow_root", "kernel_cache", "ro,bogus", "blkdev"] {
            assert!(
                matches!(parse_mount_options(raw, true), Err(OptionError::Unknown(_))),
                "{raw}"
            );
        }
    }

    #[test]
    fn allow_other_needs_the_host_permission() {
        assert!(
            parse_mount_options("allow_other", true)
                .expect("permitted")
                .allow_other
        );

        assert!(parse_mount_options("allow_other", false).is_err());
    }

    #[test]
    fn escaped_commas_stay_inside_fsname() {
        let params = parse_mount_options(r"fsname=a\,b\\c,ro", false).expect("escaped name");

        assert_eq!(params.fsname.as_deref(), Some(r"a,b\c"));
        assert!(params.read_only);
    }

    #[test]
    fn malformed_values_are_refused() {
        for raw in ["max_read=big", "fsname=", "fsname=a\nb", "blksize=-1"] {
            assert!(
                matches!(
                    parse_mount_options(raw, false),
                    Err(OptionError::Invalid(_))
                ),
                "{raw}"
            );
        }
    }
}
