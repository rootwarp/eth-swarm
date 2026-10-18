//! The credential shapes on real Linux filesystems, as root playing the service's user.
//!
//! systemd mounts `/run/credentials/<unit>` as its own tmpfs (ramfs on old kernels), writes
//! the credential root-owned 0400 and grants the user read with an ACL (`setfacl -m
//! u:<uid>:r`, the directory `r-x`), falling back to `chown` where the filesystem has no
//! ACLs, then remounts it read-only. These tests build both shapes that way and load them on a
//! thread running as the service's user, and check each refusal on the same mount.
//!
//! Needs root, `mount`, `setfacl`, CAP_SYS_ADMIN (a privileged throwaway container) and a
//! second UID in `ETHSWARM_OTHER_UID`; skipped otherwise, mandatory with
//! `ETHSWARM_ROOT_TESTS=1`. A kernel without `CONFIG_TMPFS_POSIX_ACL` (Docker Desktop's) has
//! no ACLs on tmpfs, so systemd uses the ownership shape there; the tmpfs ACL part is skipped
//! on such a kernel unless `ETHSWARM_REQUIRE_TMPFS_ACL=1` (CI) makes it mandatory.
#![cfg(target_os = "linux")]

use node_key::{load, CredentialError, CREDENTIAL, CREDENTIALS_ROOT};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const UNIT: &str = "ethswarm-node-key-acl-test.service";
const SECRET: [u8; 32] = [0x2b; 32];

fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

/// The service's UID, or `None` (skip) when this process cannot play it.
fn service_uid() -> Option<u32> {
    let uid = std::env::var("ETHSWARM_OTHER_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let euid = rustix::process::geteuid().as_raw();
    match uid {
        Some(uid) if euid == 0 && uid != 0 => Some(uid),
        _ => {
            skip(&format!(
                "needs root and ETHSWARM_OTHER_UID (euid {euid}, uid {uid:?})"
            ));
            None
        }
    }
}

fn skip(why: &str) {
    assert!(
        !flag("ETHSWARM_ROOT_TESTS"),
        "{why}; mandatory with ETHSWARM_ROOT_TESTS=1"
    );
    eprintln!("SKIPPED {why}");
}

fn run(args: &[&str]) {
    let status = Command::new(args[0]).args(&args[1..]).status().unwrap();
    assert!(status.success(), "{args:?}: {status}");
}

/// `setfacl -m <spec> <path>`; `false` if the filesystem has no ACLs.
fn try_setfacl(spec: &str, path: &str) -> bool {
    let out = Command::new("setfacl")
        .args(["-m", spec, path])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && stderr.contains("Operation not supported") {
        return false;
    }
    assert!(out.status.success(), "setfacl -m {spec} {path}: {stderr}");
    true
}

/// Writes the credential (root-owned) with `mode`.
fn write_credential(path: &str, mode: u32) {
    std::fs::File::create(path)
        .unwrap()
        .write_all(&SECRET)
        .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A tmpfs at `/run/credentials/<UNIT>`, unmounted and removed on drop.
struct Mount(PathBuf);

impl Mount {
    fn new() -> Self {
        let dir = Path::new(CREDENTIALS_ROOT).join(UNIT);
        std::fs::create_dir_all(&dir).unwrap();
        let mount = Mount(dir);
        run(&[
            "mount",
            "-t",
            "tmpfs",
            "-o",
            "mode=0700,nosuid,nodev,noexec",
            "tmpfs",
            mount.dir(),
        ]);
        mount
    }

    fn dir(&self) -> &str {
        self.0.to_str().unwrap()
    }

    fn file(&self) -> String {
        format!("{}/{CREDENTIAL}", self.dir())
    }

    fn read_only(&self, ro: bool) {
        let opts = if ro { "remount,ro" } else { "remount,rw" };
        run(&["mount", "-o", opts, self.dir()]);
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
        let _ = std::fs::remove_dir(&self.0);
    }
}

/// Loads `dir`'s credential on a thread running as `uid` (real, effective and saved UID and
/// GID, no supplementary groups).
fn load_as(uid: u32, dir: &str, unit: &'static str) -> Result<[u8; 32], CredentialError> {
    let dir = dir.to_owned();
    std::thread::spawn(move || {
        use rustix::process::{Gid, Uid};
        use rustix::thread::{set_thread_groups, set_thread_res_gid, set_thread_res_uid};
        let (u, g) = (Uid::from_raw(uid), Gid::from_raw(uid));
        set_thread_groups(&[]).unwrap();
        set_thread_res_gid(g, g, g).unwrap();
        set_thread_res_uid(u, u, u).unwrap();
        assert_eq!(rustix::process::geteuid().as_raw(), uid);
        load(Some(dir.as_ref()), uid, unit).map(|s| *s.expose_secret())
    })
    .join()
    .unwrap()
}

#[test]
fn both_systemd_shapes_on_a_read_only_tmpfs_load_as_the_service_user() {
    let Some(uid) = service_uid() else { return };
    let mount = Mount::new();
    let file = mount.file();
    write_credential(&file, 0o400);

    if try_setfacl(&format!("u:{uid}:r"), &file) {
        run(&["setfacl", "-m", &format!("u:{uid}:rx"), mount.dir()]);
        // Read-write: not systemd's (read-only) mount.
        let err = load_as(uid, mount.dir(), UNIT).unwrap_err();
        assert!(
            matches!(&err, CredentialError::Mount { reason, .. } if reason.contains("read-write")),
            "{err:?}"
        );
        mount.read_only(true);
        assert_eq!(load_as(uid, mount.dir(), UNIT), Ok(SECRET), "the ACL shape");
        let err = load_as(uid, mount.dir(), "ethswarm-other.service").unwrap_err();
        assert!(matches!(err, CredentialError::Mount { .. }), "{err:?}");

        // Another user in the ACL too.
        mount.read_only(false);
        run(&["setfacl", "-m", &format!("u:{}:r", uid + 1), &file]);
        mount.read_only(true);
        let err = load_as(uid, mount.dir(), UNIT).unwrap_err();
        assert!(matches!(err, CredentialError::Acl { .. }), "{err:?}");

        // A write grant for the user (the mask then allows write, and st_mode shows it).
        mount.read_only(false);
        run(&["setfacl", "-x", &format!("u:{}", uid + 1), &file]);
        run(&["setfacl", "-m", &format!("u:{uid}:rw"), &file]);
        mount.read_only(true);
        let err = load_as(uid, mount.dir(), UNIT).unwrap_err();
        assert!(
            matches!(
                err,
                CredentialError::Mode { .. } | CredentialError::Acl { .. }
            ),
            "{err:?}"
        );
        mount.read_only(false);
        run(&["setfacl", "-b", &file, mount.dir()]);
    } else {
        let why = "tmpfs without POSIX ACLs (CONFIG_TMPFS_POSIX_ACL off): systemd uses the \
                   ownership shape here; the tmpfs ACL part did not run";
        assert!(
            !flag("ETHSWARM_REQUIRE_TMPFS_ACL"),
            "{why}; ETHSWARM_REQUIRE_TMPFS_ACL=1"
        );
        eprintln!("SKIPPED {why}");
    }

    // The fallback where the filesystem has no ACLs: chown to the user, then read-only.
    let owner = Some(rustix::process::Uid::from_raw(uid));
    rustix::fs::chown(&file, owner, None).unwrap();
    rustix::fs::chown(mount.dir(), owner, None).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
    mount.read_only(true);
    assert_eq!(
        load_as(uid, mount.dir(), UNIT),
        Ok(SECRET),
        "the ownership shape"
    );
}

#[test]
fn kernel_acls_decode_to_the_systemd_shape_and_still_need_its_mount() {
    // A filesystem with ACLs that is not systemd's credentials mount (the container's /tmp):
    // a valid grant is decoded, then refused for its location; any other ACL for the ACL.
    let Some(uid) = service_uid() else { return };
    let dir = tempfile::tempdir().unwrap();
    let dir_s = dir.path().to_str().unwrap().to_owned();
    let file = format!("{dir_s}/{CREDENTIAL}");
    write_credential(&file, 0o400);
    if !try_setfacl(&format!("u:{uid}:r"), &file) {
        skip(&format!("no POSIX ACLs on {dir_s}"));
        return;
    }
    run(&["setfacl", "-m", &format!("u:{uid}:rx"), &dir_s]);
    let err = load_as(uid, &dir_s, UNIT).unwrap_err();
    assert!(
        matches!(&err, CredentialError::Mount { reason, .. } if reason.contains("accepted only from")),
        "the kernel's ACL must decode as systemd's grant: {err:?}"
    );
    run(&["setfacl", "-m", &format!("g:{uid}:r"), &file]);
    let err = load_as(uid, &dir_s, UNIT).unwrap_err();
    assert!(matches!(err, CredentialError::Acl { .. }), "{err:?}");
    // Without the grant the user cannot even open it.
    run(&["setfacl", "-b", &file]);
    let err = load_as(uid, &dir_s, UNIT).unwrap_err();
    assert!(
        matches!(err, CredentialError::Open { .. }),
        "no ACL: {err:?}"
    );
}
