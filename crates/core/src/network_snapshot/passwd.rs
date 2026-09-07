//! Eligibility for a home selected from observed NSS files.
use std::{io, path::Path};

/// Select a unique passwd home when NSS returns a successful files lookup.
///
/// These bytes must belong to the resolver's observed source graph. This parser
/// does not establish that graph, the resolver implementation, or its lifetime.
///
/// # Errors
/// Refuses non-files-first NSS, action overrides, ambiguous or malformed passwd
/// entries, missing users, and nonabsolute homes. Unsupported input stays on
/// userspace enforcement.
pub fn file_passwd_home<'a>(nsswitch: &str, passwd: &'a str, uid: u32) -> io::Result<&'a Path> {
    let unsupported = || io::Error::other("unsupported NSS passwd source");
    if !nsswitch.is_ascii()
        || nsswitch.len() > 1 << 20
        || passwd.len() > 1 << 20
        || nsswitch.contains(['\0', '\r', '\\'])
        || passwd.contains(['\0', '\r'])
    {
        return Err(unsupported());
    }
    let mut configured = false;
    for line in nsswitch.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (database, services) = line.split_once(':').ok_or_else(unsupported)?;
        // glibc stops the database name at whitespace, even without a colon.
        // Do not ignore a malformed line that it could treat as an override.
        let database = database.trim();
        if database.is_empty()
            || !database
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(unsupported());
        }
        if database != "passwd" {
            continue;
        }
        if configured {
            return Err(unsupported());
        }
        configured = true;
        let mut services = services.split_ascii_whitespace();
        // ponytail: accept the default SUCCESS=return only; parse action clauses
        // when a deployment actually needs them.
        if services.next() != Some("files")
            || !services.all(|service| {
                service
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            })
        {
            return Err(unsupported());
        }
    }
    if !configured {
        return Err(unsupported());
    }
    let mut home = None;
    for line in passwd
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || fields[0].starts_with(['+', '-'])
            || fields[0].bytes().any(|c| c.is_ascii_whitespace())
        {
            return Err(unsupported());
        }
        let decimal = |field: &str| -> io::Result<u32> {
            if field.is_empty() || !field.bytes().all(|c| c.is_ascii_digit()) {
                return Err(unsupported());
            }
            field.parse().map_err(|_| unsupported())
        };
        let entry_uid = decimal(fields[2])?;
        decimal(fields[3])?;
        if entry_uid != uid {
            continue;
        }
        let path = Path::new(fields[5]);
        if home.is_some() || !path.is_absolute() {
            return Err(unsupported());
        }
        home = Some(path);
    }
    home.ok_or_else(unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_unique_files_home_and_rejects_uncertain_selection() {
        let passwd = "root:x:0:0:root:/root:/bin/sh\ntim:x:1000:100:Tim:/home/tim:/bin/sh\n";
        for config in [
            "passwd: files",
            "passwd: files systemd # fallback\ngroup: files [SUCCESS=merge] systemd",
        ] {
            assert_eq!(
                file_passwd_home(config, passwd, 1000).unwrap(),
                Path::new("/home/tim")
            );
        }
        for config in [
            "",
            "passwd: systemd files",
            "passwd: files [SUCCESS=continue] systemd",
            "passwd: files [!NOTFOUND=continue] systemd",
            "passwd: files\npasswd: systemd",
            "passwd: files\npasswd ignored: systemd\n",
            "passwd: files\\\n systemd",
            "passwd: files\0",
            "passwd\u{a0}: files",
        ] {
            assert!(
                file_passwd_home(config, passwd, 1000).is_err(),
                "{config:?}"
            );
        }
        for invalid in [
            passwd.replace("1000", "1001"),
            format!("{passwd}duplicate:x:01000:100:Other:/elsewhere:/bin/sh\n"),
            passwd.replace("/home/tim", "relative"),
            passwd.replace("1000", "4294967296"),
            passwd.replace("1000", "+1000"),
            passwd.replace(":100:", ":bad:"),
            passwd.replace("tim:", "+tim:"),
            passwd.replace("/home/tim", "/home/tim\0/other"),
        ] {
            assert!(
                file_passwd_home("passwd: files systemd", &invalid, 1000).is_err(),
                "{invalid:?}"
            );
        }
    }
}
