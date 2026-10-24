//! The OS identity the session checks: the UID and primary GID of the session user
//! (`getpwnam_r(3)` of the config's `run_as`, [`user_of`]), the process's own real, effective
//! and saved UIDs ([`process_uids`]), and its GIDs and supplementary groups ([`process_gids`]).
//!
//! The lookup goes through the system's name service (NSS on Linux, Directory Services on
//! macOS), as `id -u <name>` does. rustix has no `getpwnam` and no `getresuid`, so this module
//! calls libc, and it holds the only `unsafe` code of the crate. The entry's other fields
//! (home, shell, GECOS) are never read or logged: only `pw_uid` and `pw_gid` leave the call.
//!
//! On Linux `getresuid(2)` gives all three UIDs. macOS has no call that reads the saved UID, so
//! there the saved UID is unknown (`None`) and only the real and effective UIDs are compared: a
//! process that a setuid program or root left with another saved UID is not detected on macOS.
//! The same holds for the GIDs: `getresgid(2)` on Linux, the real and effective GIDs elsewhere.
//! The supplementary groups come from `getgroups(2)` on both.
//!
//! The record buffer starts at [`INITIAL_BUFFER`] bytes and doubles on `ERANGE` up to
//! [`MAX_BUFFER`]; a record larger than that is an error, never a truncated read.

use std::ffi::CString;

/// The first record buffer: far above a local account's entry.
pub const INITIAL_BUFFER: usize = 1024;
/// The largest record buffer `getpwnam_r` is given.
pub const MAX_BUFFER: usize = 1 << 20;
/// The longest user name accepted: Linux `useradd` allows 32 bytes.
pub const MAX_NAME_LEN: usize = 32;

/// Why the session user has no UID. Each names the user, never another field of the entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UserError {
    /// Not a portable user name: 1 to [`MAX_NAME_LEN`] bytes of `[A-Za-z0-9._-]`, not
    /// starting with `-`.
    #[error(
        "run_as: {0:?} is not a user name (1 to 32 of A-Z a-z 0-9 . _ -, not starting with -)"
    )]
    InvalidName(String),
    /// The system knows no such user.
    #[error("run_as: no OS user {0:?}: create it, or name the session's own user")]
    NotFound(String),
    /// The lookup failed.
    #[error("run_as: cannot look up OS user {user:?}: {reason}")]
    Lookup {
        /// The user name.
        user: String,
        /// Why (the `errno` text, or the buffer cap).
        reason: String,
    },
}

/// The real, effective and saved UIDs of a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessUids {
    /// The real UID.
    pub real: u32,
    /// The effective UID: what file and key checks use.
    pub effective: u32,
    /// The saved set-user-ID; `None` where the platform cannot read it (macOS).
    pub saved: Option<u32>,
}

impl ProcessUids {
    /// All three UIDs set to `uid`.
    pub fn same(uid: u32) -> Self {
        Self {
            real: uid,
            effective: uid,
            saved: Some(uid),
        }
    }

    /// Whether the real UID, and the saved UID where known, equal the effective UID: else the
    /// process can switch back to another UID.
    pub fn all_equal(&self) -> bool {
        self.real == self.effective && self.saved.is_none_or(|s| s == self.effective)
    }
}

/// This process's UIDs: `getresuid(2)` on Linux, `getuid` and `geteuid` elsewhere (no saved
/// UID; see the module docs).
pub fn process_uids() -> ProcessUids {
    #[cfg(target_os = "linux")]
    {
        let (mut real, mut effective, mut saved): (libc::uid_t, libc::uid_t, libc::uid_t) =
            (0, 0, 0);
        // SAFETY: the three pointers are valid for writes of a `uid_t` for the whole call.
        // `getresuid` cannot fail with valid pointers (getresuid(2): EFAULT only).
        let rc = unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) };
        if rc == 0 {
            return ProcessUids {
                real,
                effective,
                saved: Some(saved),
            };
        }
    }
    ProcessUids {
        real: rustix::process::getuid().as_raw(),
        effective: rustix::process::geteuid().as_raw(),
        saved: None,
    }
}

/// The real, effective and saved GIDs of a process, and its supplementary groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessGids {
    /// The real GID.
    pub real: u32,
    /// The effective GID.
    pub effective: u32,
    /// The saved set-group-ID; `None` where the platform cannot read it (macOS).
    pub saved: Option<u32>,
    /// The supplementary groups (`getgroups`).
    pub groups: Vec<u32>,
}

impl ProcessGids {
    /// All three GIDs set to `gid`, and no supplementary group.
    pub fn same(gid: u32) -> Self {
        Self {
            real: gid,
            effective: gid,
            saved: Some(gid),
            groups: Vec::new(),
        }
    }

    /// Whether the real GID, and the saved GID where known, equal the effective GID.
    pub fn all_equal(&self) -> bool {
        self.real == self.effective && self.saved.is_none_or(|s| s == self.effective)
    }

    /// Whether any of the three GIDs is 0.
    pub fn has_root_group(&self) -> bool {
        self.real == 0 || self.effective == 0 || self.saved == Some(0)
    }
}

/// This process's GIDs (`getresgid(2)` on Linux, `getgid` and `getegid` elsewhere: no saved
/// GID) and its supplementary groups.
///
/// # Errors
///
/// `getgroups` failed.
pub fn process_gids() -> Result<ProcessGids, String> {
    let groups = rustix::process::getgroups()
        .map_err(|e| format!("getgroups: {e}"))?
        .into_iter()
        .map(|g| g.as_raw())
        .collect();
    #[cfg(target_os = "linux")]
    {
        let (mut real, mut effective, mut saved): (libc::gid_t, libc::gid_t, libc::gid_t) =
            (0, 0, 0);
        // SAFETY: the three pointers are valid for writes of a `gid_t` for the whole call.
        // `getresgid` cannot fail with valid pointers (getresgid(2): EFAULT only).
        let rc = unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) };
        if rc == 0 {
            return Ok(ProcessGids {
                real,
                effective,
                saved: Some(saved),
                groups,
            });
        }
    }
    Ok(ProcessGids {
        real: rustix::process::getgid().as_raw(),
        effective: rustix::process::getegid().as_raw(),
        saved: None,
        groups,
    })
}

/// The fields of a passwd entry the session reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserEntry {
    /// `pw_uid`.
    pub uid: u32,
    /// `pw_gid`: the primary GID.
    pub gid: u32,
}

/// Whether `name` is a portable user name (see [`UserError::InvalidName`]).
pub fn is_valid_name(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The UID of the OS user `name`: [`user_of`]'s `uid`.
///
/// # Errors
///
/// As [`user_of`].
pub fn uid_of(name: &str) -> Result<u32, UserError> {
    user_of(name).map(|entry| entry.uid)
}

/// The UID and the primary GID of the OS user `name`, from one passwd entry.
///
/// # Errors
///
/// [`UserError::InvalidName`] before any lookup, [`UserError::NotFound`] if the system has no
/// such user, [`UserError::Lookup`] if the lookup fails or the record is over [`MAX_BUFFER`].
pub fn user_of(name: &str) -> Result<UserEntry, UserError> {
    if !is_valid_name(name) {
        return Err(UserError::InvalidName(name.to_owned()));
    }
    let c_name = CString::new(name).map_err(|_| UserError::InvalidName(name.to_owned()))?;
    let lookup = |reason: String| UserError::Lookup {
        user: name.to_owned(),
        reason,
    };
    let mut buffer: Vec<libc::c_char> = vec![0; INITIAL_BUFFER];
    loop {
        // SAFETY: `libc::passwd` is plain old data (integers and raw pointers), so the zeroed
        // value is valid; `getpwnam_r` overwrites it before it is read.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `c_name` is a NUL-terminated string that outlives the call. `entry` and
        // `found` are valid for writes. `buffer` is valid for writes of `buffer.len()` bytes,
        // and the strings of `entry` point into it, but only `pw_uid` and `pw_gid` (integers) are
        // read, and
        // only while `buffer` is alive. `getpwnam_r` is the reentrant form, so no static
        // storage is shared with another thread.
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        match rc {
            0 if found.is_null() => return Err(UserError::NotFound(name.to_owned())),
            0 => {
                return Ok(UserEntry {
                    uid: entry.pw_uid,
                    gid: entry.pw_gid,
                })
            }
            // Some systems report "no such user" as one of these (getpwnam_r(3)).
            libc::ENOENT | libc::ESRCH => return Err(UserError::NotFound(name.to_owned())),
            libc::ERANGE if buffer.len() < MAX_BUFFER => {
                let len = (buffer.len() * 2).min(MAX_BUFFER);
                buffer = vec![0; len];
            }
            libc::ERANGE => {
                return Err(lookup(format!(
                    "the record is over the {MAX_BUFFER}-byte buffer"
                )))
            }
            errno => return Err(lookup(std::io::Error::from_raw_os_error(errno).to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The process's UIDs: real and effective as rustix reads them, and the saved UID where the
    /// platform has `getresuid` (Linux; macOS has none).
    #[test]
    fn process_uids_are_this_process() {
        let uids = process_uids();
        assert_eq!(uids.real, rustix::process::getuid().as_raw());
        assert_eq!(uids.effective, rustix::process::geteuid().as_raw());
        assert_eq!(uids.saved.is_some(), cfg!(target_os = "linux"));
        assert!(ProcessUids::same(7).all_equal());
        assert_eq!(
            ProcessUids::same(7),
            ProcessUids {
                real: 7,
                effective: 7,
                saved: Some(7)
            }
        );
        for mixed in [
            ProcessUids {
                real: 0,
                effective: 7,
                saved: Some(7),
            },
            ProcessUids {
                real: 7,
                effective: 7,
                saved: Some(0),
            },
            ProcessUids {
                real: 8,
                effective: 7,
                saved: None,
            },
        ] {
            assert!(!mixed.all_equal(), "{mixed:?}");
        }
        assert!(ProcessUids {
            real: 7,
            effective: 7,
            saved: None
        }
        .all_equal());
    }

    /// The process's GIDs and supplementary groups, as rustix reads them; the saved GID only
    /// where the platform has `getresgid` (Linux).
    #[test]
    fn process_gids_are_this_process() {
        let gids = process_gids().unwrap();
        assert_eq!(gids.real, rustix::process::getgid().as_raw());
        assert_eq!(gids.effective, rustix::process::getegid().as_raw());
        assert_eq!(gids.saved.is_some(), cfg!(target_os = "linux"));
        let groups: Vec<u32> = rustix::process::getgroups()
            .unwrap()
            .into_iter()
            .map(|g| g.as_raw())
            .collect();
        assert_eq!(gids.groups, groups);
        assert!(ProcessGids::same(7).all_equal());
        assert!(ProcessGids::same(7).groups.is_empty());
        for mixed in [
            ProcessGids {
                real: 0,
                ..ProcessGids::same(7)
            },
            ProcessGids {
                saved: Some(8),
                ..ProcessGids::same(7)
            },
        ] {
            assert!(!mixed.all_equal(), "{mixed:?}");
        }
        assert!(ProcessGids {
            saved: None,
            ..ProcessGids::same(7)
        }
        .all_equal());
    }

    /// One passwd entry gives the session user's UID and its primary GID: `root` is 0 and 0.
    #[test]
    fn the_entry_gives_the_uid_and_the_primary_gid() {
        assert_eq!(user_of("root"), Ok(UserEntry { uid: 0, gid: 0 }));
        assert_eq!(
            user_of("ethswarm-no-such-u"),
            Err(UserError::NotFound("ethswarm-no-such-u".into()))
        );
        assert_eq!(user_of("a b"), Err(UserError::InvalidName("a b".into())));
    }

    /// `root` is UID 0 on Linux and macOS.
    #[test]
    fn root_is_uid_0() {
        assert_eq!(uid_of("root"), Ok(0));
    }

    /// The user the tests run as resolves to the effective UID (`id -un` names it). Skipped,
    /// with the reason printed, if `id -un` gives no portable name.
    #[test]
    fn the_test_user_resolves_to_the_euid() {
        let out = std::process::Command::new("id")
            .arg("-un")
            .output()
            .unwrap();
        let name = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        if !out.status.success() || !is_valid_name(&name) {
            // As under `docker --user <uid>` with no passwd entry.
            eprintln!("the_test_user_resolves_to_the_euid: skipped: no portable `id -un` name");
            return;
        }
        assert_eq!(
            uid_of(&name),
            Ok(rustix::process::geteuid().as_raw()),
            "{name}"
        );
    }

    #[test]
    fn an_unknown_user_is_not_found() {
        let name = "ethswarm-no-such-u";
        assert_eq!(uid_of(name), Err(UserError::NotFound(name.into())));
        assert_eq!(
            UserError::NotFound(name.into()).to_string(),
            "run_as: no OS user \"ethswarm-no-such-u\": create it, or name the session's own user"
        );
    }

    /// A name that is not portable is refused before the lookup: a NUL byte cannot reach C.
    #[test]
    fn a_name_that_is_not_portable_is_refused() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        for name in ["", "-x", "a\0b", "a b", "a/b", "a:b", "é", long.as_str()] {
            assert!(!is_valid_name(name), "{name:?}");
            assert_eq!(
                uid_of(name),
                Err(UserError::InvalidName(name.into())),
                "{name:?}"
            );
        }
        for name in ["m2a-session", "a", "_x", "u.1", &"a".repeat(MAX_NAME_LEN)] {
            assert!(is_valid_name(name), "{name:?}");
        }
    }
}
