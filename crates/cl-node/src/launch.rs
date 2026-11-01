//! `cl-node launch --foreground`: the eight services as children of cl-node, for containers
//! without systemd. It does for each child what its unit asks of systemd, as far as a container
//! needs it:
//!
//! - **Order and readiness.** The children start in [`Service::START_ORDER`], each only after
//!   the one before sent `READY=1` to its own `NOTIFY_SOCKET` (a datagram socket in a 0700
//!   directory of its own) within the ready timeout. Only a datagram whose `SCM_CREDENTIALS` name
//!   the child's own pid counts, which is the units' `NotifyAccess=main`.
//! - **Environment.** Cleared: a child sees `PATH` (systemd's default), `NOTIFY_SOCKET`,
//!   `RUNTIME_DIRECTORY` (`<runtime-dir>/cl-<svc>`, 0750) and, only for a credential owner
//!   ([`Service::credentials`]), `CREDENTIALS_DIRECTORY`: a 0700 directory holding copies (0400)
//!   of its own credentials only, removed when cl-node exits. Its working directory is `/`, its
//!   umask 0077 (the units' `UMask=`).
//! - **Users.** As root, each child drops to its unit's user, group and caller groups (looked up
//!   by name) before exec; a missing name, or one that is root, refuses the launch before
//!   anything starts. Never as root: a failed drop fails the spawn. As any other user, the
//!   children run as that user.
//! - **Stopping.** Each child leads its own process group. Once one exits (before or after
//!   READY=1), misses its deadline, or cl-node gets SIGTERM or SIGINT, the running ones are
//!   stopped in reverse start order: SIGTERM to the group, SIGKILL after the grace. Whatever a
//!   child that exited leaves in its group is SIGKILLed before the child is reaped (its pid still
//!   pins the group id), so nothing outlives cl-node. Exit 0 after a signal, 1 otherwise.
//!
//! It holds no state: everything it creates but the runtime directories goes with it.

use std::collections::BTreeSet;
use std::ffi::{c_char, c_int, CString};
use std::fs;
use std::io::{self, IoSliceMut, Write as _};
use std::mem::MaybeUninit;
use std::os::unix::fs::{chown, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use rustix::fs::Mode;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
use rustix::process::{kill_process_group, waitid, Gid, Pid, Signal, Uid, WaitId, WaitIdOptions};
use tokio::io::Interest;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep_until, Instant};

use crate::cli::Launch;
use crate::units::Service;

/// The `PATH` of every child: systemd's default for system services.
pub const CHILD_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Where cl-node keeps the children's sockets and credential copies, under the runtime dir.
const PRIVATE: &str = ".cl-node";

/// The user, group and supplementary groups a child runs as when cl-node is root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

/// Each service's identity from its unit (`User=`, `Group=`, `SupplementaryGroups=`), in start
/// order, through `user` and `group` (name → id). Refuses, naming every one, a name that does
/// not resolve or resolves to root.
pub fn identities(
    user: impl Fn(&str) -> Option<u32>,
    group: impl Fn(&str) -> Option<u32>,
) -> Result<Vec<Identity>, String> {
    let mut refused = BTreeSet::new();
    let mut need = |id: Option<u32>, kind: &str, name: &str| match id {
        Some(id) if id != 0 => id,
        found => {
            let root = if found.is_some() { " is root" } else { "" };
            refused.insert(format!("{kind} {name}{root}"));
            0
        }
    };
    let ids: Vec<Identity> = Service::START_ORDER
        .iter()
        .map(|svc| Identity {
            uid: need(user(&svc.user()), "user", &svc.user()),
            gid: need(group(&svc.user()), "group", &svc.user()),
            groups: svc
                .caller_groups()
                .iter()
                .map(|g| need(group(g), "group", g))
                .collect(),
        })
        .collect();
    if refused.is_empty() {
        return Ok(ids);
    }
    let refused: Vec<String> = refused.into_iter().collect();
    Err(format!(
        "as root every service runs as its unit's user, but: {} (create them, or run as \
         another user for a test)",
        refused.join(", ")
    ))
}

/// `getpwnam_r` or `getgrnam_r` of `name`, through NSS like systemd's `User=`.
fn nss_id<T>(
    name: &str,
    get: unsafe extern "C" fn(*const c_char, *mut T, *mut c_char, usize, *mut *mut T) -> c_int,
    id: fn(&T) -> u32,
) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let mut size = 16 * 1024;
    loop {
        let mut buf = vec![0 as c_char; size];
        let mut entry = MaybeUninit::<T>::uninit();
        let mut found = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call and `buf` is `size` long; the entry is read
        // only when the call returned it.
        let rc = unsafe {
            get(
                name.as_ptr(),
                entry.as_mut_ptr(),
                buf.as_mut_ptr(),
                size,
                &mut found,
            )
        };
        if rc == libc::ERANGE && size < 1 << 20 {
            size *= 4;
            continue;
        }
        // SAFETY: a non-null `found` is `entry`, filled in.
        return (rc == 0 && !found.is_null()).then(|| id(unsafe { entry.assume_init_ref() }));
    }
}

/// What one child gets, made before any child starts.
struct Prepared {
    svc: Service,
    identity: Option<Identity>,
    notify: UnixDatagram,
    notify_path: PathBuf,
    runtime: PathBuf,
    credentials: Option<PathBuf>,
}

/// `<runtime-dir>/.cl-node`: the children's sockets and credential copies, gone with cl-node.
struct PrivateDir(PathBuf);

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn io_err(what: impl std::fmt::Display) -> impl FnOnce(io::Error) -> String {
    move |e| format!("{what}: {e}")
}

/// Creates `path` with `mode` exactly (not through the umask), owned by `owner` if given.
fn make_dir(path: &Path, mode: u32, owner: Option<&Identity>) -> Result<(), String> {
    fs::create_dir(path).map_err(io_err(path.display()))?;
    give(path, mode, owner)
}

fn give(path: &Path, mode: u32, owner: Option<&Identity>) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_err(path.display()))?;
    match owner {
        Some(id) => chown(path, Some(id.uid), Some(id.gid)).map_err(io_err(path.display())),
        None => Ok(()),
    }
}

/// Reads the credentials, makes the runtime directories and each child's private directory.
fn prepare(
    launch: &Launch,
    private: &Path,
    ids: Option<Vec<Identity>>,
) -> Result<Vec<Prepared>, String> {
    // Every credential first: a missing one refuses the launch before anything is made.
    let mut secrets = Vec::new();
    for svc in Service::START_ORDER {
        for name in svc.credentials() {
            let path = launch.credentials_dir.join(name);
            let bytes =
                fs::read(&path).map_err(io_err(format!("credential {}", path.display())))?;
            secrets.push((svc, *name, bytes));
        }
    }
    if !launch.runtime_dir.exists() {
        fs::create_dir_all(&launch.runtime_dir).map_err(io_err(launch.runtime_dir.display()))?;
        give(&launch.runtime_dir, 0o755, None)?;
    }
    // A directory a killed launch left behind holds only what this one replaces.
    if private.exists() {
        fs::remove_dir_all(private).map_err(io_err(private.display()))?;
    }
    make_dir(private, 0o711, None)?;
    let mut out = Vec::new();
    for (i, svc) in Service::START_ORDER.into_iter().enumerate() {
        let identity = ids.as_ref().map(|ids| ids[i].clone());
        let runtime = launch.runtime_dir.join(svc.binary());
        if !runtime.exists() {
            make_dir(&runtime, 0o750, identity.as_ref())?;
        }
        let own = private.join(svc.short());
        make_dir(&own, 0o700, identity.as_ref())?;
        let notify_path = own.join("notify");
        let notify = UnixDatagram::bind(&notify_path).map_err(io_err(notify_path.display()))?;
        give(&notify_path, 0o600, identity.as_ref())?;
        rustix::net::sockopt::set_socket_passcred(&notify, true)
            .map_err(|e| format!("SO_PASSCRED: {e}"))?;
        notify
            .set_nonblocking(true)
            .map_err(io_err("notify socket"))?;
        let mut credentials = None;
        for (_, name, bytes) in secrets.iter().filter(|(s, _, _)| *s == svc) {
            let dir = own.join("credentials");
            if credentials.is_none() {
                make_dir(&dir, 0o700, identity.as_ref())?;
            }
            let path = dir.join(name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&path)
                .map_err(io_err(path.display()))?;
            file.write_all(bytes).map_err(io_err(path.display()))?;
            give(&path, 0o400, identity.as_ref())?;
            credentials = Some(dir);
        }
        out.push(Prepared {
            svc,
            identity,
            notify,
            notify_path,
            runtime,
            credentials,
        });
    }
    Ok(out)
}

fn spawn(p: &Prepared, bin_dir: &Path) -> io::Result<Child> {
    let mut cmd = Command::new(bin_dir.join(p.svc.binary()));
    cmd.env_clear()
        .env("PATH", CHILD_PATH)
        .env("NOTIFY_SOCKET", &p.notify_path)
        .env("RUNTIME_DIRECTORY", &p.runtime)
        .current_dir("/")
        .stdin(Stdio::null())
        .process_group(0);
    if let Some(dir) = &p.credentials {
        cmd.env("CREDENTIALS_DIRECTORY", dir);
    }
    let id = p.identity.as_ref();
    let ids = id.map(|id| (Uid::from_raw(id.uid), Gid::from_raw(id.gid)));
    let groups: Vec<Gid> = id.map_or(Vec::new(), |id| {
        id.groups.iter().map(|g| Gid::from_raw(*g)).collect()
    });
    let parent = rustix::process::getpid();
    // SAFETY: runs in the forked child before exec and only makes raw syscalls (no allocation,
    // no lock). Groups first, then the gid, then the uid: once the uid is not root the others
    // cannot change. A failure fails the spawn, so no child runs as root. The parent-death
    // signal comes after, as a credential change clears it: a child dies with cl-node (with the
    // thread that forked it, which the current-thread runtime keeps the main thread).
    unsafe {
        cmd.pre_exec(move || {
            default_signals();
            if let Some((uid, gid)) = ids {
                rustix::thread::set_thread_groups(&groups)?;
                rustix::thread::set_thread_res_gid(gid, gid, gid)?;
                rustix::thread::set_thread_res_uid(uid, uid, uid)?;
            }
            rustix::process::set_parent_process_death_signal(Some(Signal::KILL))?;
            match rustix::process::getppid() {
                Some(ppid) if ppid == parent => Ok(()),
                _ => Err(io::Error::other("cl-node exited")),
            }
        });
    }
    cmd.spawn()
}

/// Empties this thread's signal mask: whatever started cl-node may have blocked SIGTERM.
fn unblock_signals() {
    // SAFETY: sigemptyset and pthread_sigmask on a zeroed, valid set.
    unsafe {
        let mut empty: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut empty);
        libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
    }
}

/// A service's signals as systemd leaves them: none blocked, every disposition the default but
/// SIGPIPE's, ignored (`IgnoreSIGPIPE=yes`). Only signal syscalls: safe between fork and exec.
fn default_signals() {
    // SAFETY: sigaction on a zeroed, valid struct; SIGKILL, SIGSTOP and libc's own signals
    // refuse, and keep what they have.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        for sig in 1..=64 {
            let pipe = sig == libc::SIGPIPE;
            action.sa_sigaction = if pipe { libc::SIG_IGN } else { libc::SIG_DFL };
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
    unblock_signals();
}

/// Reads every queued datagram; `Ok(true)` once one from `pid` has the line `READY=1`.
/// `WouldBlock` when the queue is empty without one.
fn ready_from(socket: &tokio::net::UnixDatagram, pid: Pid) -> io::Result<bool> {
    loop {
        let mut buf = [0u8; 4096];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = rustix::net::recvmsg(socket, &mut iov, &mut control, RecvFlags::DONTWAIT)?;
        let sender = control.drain().find_map(|m| match m {
            RecvAncillaryMessage::ScmCredentials(cred) => Some(cred.pid),
            _ => None,
        });
        let ready = buf[..msg.bytes]
            .split(|b| *b == b'\n')
            .any(|l| l == b"READY=1");
        if ready && sender == Some(pid) {
            return Ok(true);
        }
    }
}

struct Running {
    svc: Service,
    child: Child,
    status: Option<ExitStatus>,
}

/// What ended a wait.
enum Event {
    Signal,
    Ready,
    Exited(String),
    Timeout,
}

struct Supervisor {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    chld: tokio::signal::unix::Signal,
    running: Vec<Running>,
}

impl Supervisor {
    /// Reaps every child that exited, after SIGKILLing what it left in its process group.
    /// Describes the first one.
    fn reap(&mut self) -> Option<String> {
        let mut first = None;
        let peek = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
        for r in self.running.iter_mut().filter(|r| r.status.is_none()) {
            let pid = Pid::from_child(&r.child);
            if let Ok(Some(_)) = waitid(WaitId::Pid(pid), peek) {
                // Unreaped, its pid still names the group: no other group can have that id.
                let _ = kill_process_group(pid, Signal::KILL);
                let Ok(status) = r.child.wait() else { continue };
                r.status = Some(status);
                first.get_or_insert(format!("{} exited ({status})", r.svc.binary()));
            }
        }
        first
    }

    /// Waits for a signal, a child's exit, READY=1 on `notify` from its child, or `deadline`.
    async fn next(
        &mut self,
        notify: Option<(&tokio::net::UnixDatagram, Pid)>,
        deadline: Option<Instant>,
    ) -> Result<Event, String> {
        let far = Instant::now() + Duration::from_secs(1 << 30);
        loop {
            if let Some(exited) = self.reap() {
                return Ok(Event::Exited(exited));
            }
            tokio::select! {
                _ = self.term.recv() => return Ok(Event::Signal),
                _ = self.int.recv() => return Ok(Event::Signal),
                _ = self.chld.recv() => {}
                r = async { notify.unwrap().0.readable().await }, if notify.is_some() => {
                    r.map_err(io_err("notify socket"))?;
                    let (socket, pid) = notify.unwrap();
                    match socket.try_io(Interest::READABLE, || ready_from(socket, pid)) {
                        Ok(_) => return Ok(Event::Ready),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => return Err(format!("notify socket: {e}")),
                    }
                }
                _ = sleep_until(deadline.unwrap_or(far)) => return Ok(Event::Timeout),
            }
        }
    }

    /// Stops the running children in reverse start order: SIGTERM to the group, SIGKILL after
    /// `grace`, and reaps each.
    async fn stop(&mut self, grace: Duration) {
        for i in (0..self.running.len()).rev() {
            self.reap();
            let r = &self.running[i];
            if r.status.is_some() {
                continue;
            }
            let (name, pid) = (r.svc.binary(), Pid::from_child(&r.child));
            eprintln!("cl-node: stopping {name}");
            let _ = kill_process_group(pid, Signal::TERM);
            let mut deadline = Some(Instant::now() + grace);
            while self.running[i].status.is_none() {
                let until =
                    deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(1 << 30));
                tokio::select! {
                    _ = self.chld.recv() => {}
                    _ = sleep_until(until), if deadline.is_some() => {
                        eprintln!("cl-node: {name} did not stop within {grace:?}: SIGKILL");
                        let _ = kill_process_group(pid, Signal::KILL);
                        deadline = None;
                    }
                }
                self.reap();
            }
        }
    }
}

/// Starts the children in order, then waits; stops them all in reverse at the end.
async fn supervise(prepared: Vec<Prepared>, launch: &Launch) -> Result<(), String> {
    let sig = |kind| signal(kind).map_err(io_err("signal handler"));
    let mut sup = Supervisor {
        term: sig(SignalKind::terminate())?,
        int: sig(SignalKind::interrupt())?,
        chld: sig(SignalKind::child())?,
        running: Vec::new(),
    };
    let mut outcome = Ok(());
    let mut stopped = false;
    for p in &prepared {
        let name = p.svc.binary();
        // A failure here stops the ones already started, like any other.
        let started = p.notify.try_clone().and_then(|socket| {
            let notify = tokio::net::UnixDatagram::from_std(socket)?;
            Ok((notify, spawn(p, launch.config.bin_dir())?))
        });
        let (notify, child) = match started {
            Ok(started) => started,
            Err(e) => {
                outcome = Err(format!("cannot start {name}: {e}"));
                break;
            }
        };
        let pid = Pid::from_child(&child);
        eprintln!("cl-node: started {name} (pid {})", child.id());
        sup.running.push(Running {
            svc: p.svc,
            child,
            status: None,
        });
        let deadline = Instant::now() + launch.ready_timeout;
        match sup.next(Some((&notify, pid)), Some(deadline)).await {
            Ok(Event::Ready) => eprintln!("cl-node: {name} is ready"),
            Ok(Event::Signal) => stopped = true,
            Ok(Event::Exited(e)) => outcome = Err(e),
            Ok(Event::Timeout) => {
                outcome = Err(format!(
                    "{name} sent no READY=1 within {:?}",
                    launch.ready_timeout
                ))
            }
            Err(e) => outcome = Err(e),
        }
        if stopped || outcome.is_err() {
            break;
        }
    }
    if !stopped && outcome.is_ok() {
        eprintln!("cl-node: all eight services are ready");
        outcome = match sup.next(None, None).await {
            Ok(Event::Exited(e)) => Err(e),
            Err(e) => Err(e),
            Ok(_) => Ok(()),
        };
    }
    if let Err(e) = &outcome {
        eprintln!("cl-node: {e}; stopping the others");
    }
    sup.stop(launch.stop_grace).await;
    outcome
}

/// Launches the services and supervises them until one exits or a signal stops them all.
/// `Ok` after SIGTERM or SIGINT; `Err` names what failed.
pub fn run(launch: &Launch) -> Result<(), String> {
    let ids = if rustix::process::geteuid().is_root() {
        let user = |n: &str| nss_id(n, libc::getpwnam_r, |p: &libc::passwd| p.pw_uid);
        let group = |n: &str| nss_id(n, libc::getgrnam_r, |g: &libc::group| g.gr_gid);
        Some(identities(user, group)?)
    } else {
        None
    };
    unblock_signals();
    // The units' UMask=: the children inherit it; cl-node sets its own modes explicitly.
    rustix::process::umask(Mode::from_raw_mode(0o077));
    eprintln!(
        "cl-node: launching the eight services (network {})",
        launch.config.network()
    );
    let private = PrivateDir(launch.runtime_dir.join(PRIVATE));
    let prepared = prepare(launch, &private.0, ids)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io_err("tokio runtime"))?;
    runtime.block_on(supervise(prepared, launch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(table: &'a [(&'a str, u32)]) -> impl Fn(&str) -> Option<u32> + 'a {
        |name| table.iter().find(|(n, _)| *n == name).map(|(_, id)| *id)
    }

    /// Every unit user and group, ids 1000 + start position.
    fn all() -> Vec<(String, u32)> {
        Service::START_ORDER
            .iter()
            .zip(1000..)
            .map(|(s, id)| (s.user(), id))
            .collect()
    }

    fn table(names: &[(String, u32)]) -> Vec<(&str, u32)> {
        names.iter().map(|(n, id)| (n.as_str(), *id)).collect()
    }

    #[test]
    fn identities_follow_the_units() {
        let names = all();
        let t = table(&names);
        let ids = identities(lookup(&t), lookup(&t)).unwrap();
        assert_eq!(ids.len(), 8);
        // cl-chain (third): its own ids, and the groups of cl-engine, cl-p2p and cl-verify.
        assert_eq!(
            ids[2],
            Identity {
                uid: 1002,
                gid: 1002,
                groups: vec![1001, 1005, 1000],
            }
        );
        // cl-verify calls no one.
        assert_eq!(ids[0].groups, Vec::<u32>::new());
    }

    #[test]
    fn identities_refuse_missing_names_and_root() {
        let names = all();
        let mut users = table(&names);
        users.retain(|(n, _)| *n != "ethswarm-verify" && *n != "ethswarm-api");
        let groups = table(&names);
        let err = identities(lookup(&users), lookup(&groups)).unwrap_err();
        assert!(err.contains("user ethswarm-verify"), "{err}");
        assert!(err.contains("user ethswarm-api"), "{err}");

        let mut groups = table(&names);
        groups.retain(|(n, _)| *n != "ethswarm-p2p");
        let err = identities(lookup(&table(&names)), lookup(&groups)).unwrap_err();
        assert!(err.contains("group ethswarm-p2p"), "{err}");

        for (who, uid_zero) in [("ethswarm-store", true), ("ethswarm-chain", false)] {
            let mut zeroed = table(&names);
            for entry in zeroed.iter_mut().filter(|(n, _)| *n == who) {
                entry.1 = 0;
            }
            let (users, groups) = if uid_zero {
                (zeroed, table(&names))
            } else {
                (table(&names), zeroed)
            };
            let err = identities(lookup(&users), lookup(&groups)).unwrap_err();
            assert!(err.contains(&format!("{who} is root")), "{err}");
        }
    }
}
