//! Mutual peer authentication on Unix sockets, the method ACL, and the service socket directory.
//!
//! Each case first runs with this process's single UID, injecting the "other" UID through the
//! configuration (expect a server UID that is not ours, allow a method to a UID that is not
//! ours): the kernel's real credentials of the connection are what gets refused. The multi-UID
//! part of a case needs root on Linux, where one thread can take another user's credentials
//! (credentials are per thread there): it skips with a message otherwise, and is mandatory with
//! `ETHSWARM_ROOT_TESTS=1` (the `root-tests` CI job, which also creates three throwaway users and
//! exports `ETHSWARM_{CHAIN,API,OTHER}_{UID,GID}`). Locally: `sudo -E cargo test -p ipc --test
//! peercred`.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ethswarm_proto::common::ErrorCode;
use ethswarm_proto::sync::sync_service_client::SyncServiceClient;
use ethswarm_proto::sync::sync_service_server::{SyncService, SyncServiceServer};
use ethswarm_proto::sync::{
    GetSyncProgressRequest, GetSyncProgressResponse, StartBackfillRequest, StartBackfillResponse,
};
use ipc::acl::{AclLayer, MethodAcl};
use ipc::peercred::{effective_gid, effective_uid, PeerCredError};
use ipc::uds::{self, BindError, Ownership, SocketDir};
use ipc::ContractError;
use tokio::io::AsyncReadExt;
use tokio::sync::oneshot;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::transport::Channel;
use tonic::{Code, Request, Response, Status};

const PROGRESS: &str = "/ethswarm.sync.v1.SyncService/GetSyncProgress";
const BACKFILL: &str = "/ethswarm.sync.v1.SyncService/StartBackfill";

fn me() -> u32 {
    effective_uid()
}

/// A UID that is not ours (and not the invalid `u32::MAX`).
fn not_me() -> u32 {
    match me().checked_add(1) {
        Some(u) if u != u32::MAX => u,
        _ => 0,
    }
}

/// A fresh runtime root: a temp dir owned by us, mode 0700.
fn runtime_root() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("uds-").tempdir().unwrap()
}

fn mode_of(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A group we may give our files to that is not our effective group, if we have one.
fn second_group() -> Option<u32> {
    rustix::process::getgroups()
        .unwrap()
        .into_iter()
        .map(rustix::process::Gid::as_raw)
        .find(|g| *g != effective_gid())
}

// ---- the multi-UID part ----------------------------------------------------------------------

/// The throwaway users of the root-tests job: (uid, gid) each.
#[derive(Clone, Copy, Debug)]
struct Users {
    /// The allowed caller (cl-chain).
    chain: (u32, u32),
    /// A caller in the socket group but not allowed on every method.
    api: (u32, u32),
    /// A user outside the group: counterfeit servers and foreign sockets.
    other: (u32, u32),
}

/// The users for the multi-UID part of `test`, or `None` (skip) without root on Linux.
fn users(test: &str) -> Option<Users> {
    let required = std::env::var("ETHSWARM_ROOT_TESTS").is_ok_and(|v| v == "1");
    let id = |name: &str| {
        std::env::var(format!("ETHSWARM_{name}"))
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
    };
    let pair = |user: &str| Some((id(&format!("{user}_UID"))?, id(&format!("{user}_GID"))?));
    let found = (|| {
        Some(Users {
            chain: pair("CHAIN")?,
            api: pair("API")?,
            other: pair("OTHER")?,
        })
    })();
    let why = if !cfg!(target_os = "linux") {
        "needs Linux (per-thread credentials)".to_owned()
    } else if me() != 0 {
        format!("needs root (euid {})", me())
    } else if found.is_none() {
        "needs ETHSWARM_{CHAIN,API,OTHER}_{UID,GID}".to_owned()
    } else {
        return found;
    };
    assert!(
        !required,
        "{test}: multi-UID part {why}; mandatory with ETHSWARM_ROOT_TESTS=1"
    );
    eprintln!(
        "SKIPPED the multi-UID part of {test}: {why} (runs in the root-tests CI job; locally \
         `sudo -E cargo test -p ipc --test peercred`)"
    );
    None
}

/// Runs `f` on a thread that holds `uid`, `gid` and the supplementary `groups` (Linux, root).
fn as_user<T: Send + 'static>(
    (uid, gid): (u32, u32),
    groups: &[u32],
    f: impl FnOnce() -> T + Send + 'static,
) -> T {
    let groups = groups.to_vec();
    std::thread::spawn(move || {
        become_user(uid, gid, &groups);
        f()
    })
    .join()
    .unwrap()
}

#[cfg(target_os = "linux")]
fn become_user(uid: u32, gid: u32, groups: &[u32]) {
    use rustix::process::{Gid, Uid};
    use rustix::thread::{set_thread_groups, set_thread_res_gid, set_thread_res_uid};
    let groups: Vec<Gid> = groups.iter().copied().map(Gid::from_raw).collect();
    set_thread_groups(&groups).unwrap();
    let g = Gid::from_raw(gid);
    set_thread_res_gid(g, g, g).unwrap();
    let u = Uid::from_raw(uid);
    set_thread_res_uid(u, u, u).unwrap();
}

#[cfg(not(target_os = "linux"))]
fn become_user(_: u32, _: u32, _: &[u32]) {
    unreachable!("users() is None off Linux");
}

/// A directory another user can create sockets in.
fn dir_for(root: &Path, name: &str, (uid, gid): (u32, u32)) -> PathBuf {
    set_mode(root, 0o755);
    let dir = root.join(name);
    std::fs::create_dir(&dir).unwrap();
    std::os::unix::fs::chown(&dir, Some(uid), Some(gid)).unwrap();
    set_mode(&dir, 0o755);
    dir
}

fn std_listener(path: PathBuf) -> std::os::unix::net::UnixListener {
    let l = std::os::unix::net::UnixListener::bind(path).unwrap();
    l.set_nonblocking(true).unwrap();
    l
}

// ---- a sync service behind the ACL --------------------------------------------------------------

#[derive(Clone, Copy)]
struct Sync;

#[tonic::async_trait]
impl SyncService for Sync {
    async fn get_sync_progress(
        &self,
        _: Request<GetSyncProgressRequest>,
    ) -> Result<Response<GetSyncProgressResponse>, Status> {
        Ok(Response::new(GetSyncProgressResponse::default()))
    }
    async fn start_backfill(
        &self,
        _: Request<StartBackfillRequest>,
    ) -> Result<Response<StartBackfillResponse>, Status> {
        Ok(Response::new(StartBackfillResponse::default()))
    }
}

/// `GetSyncProgress` for `progress`, `StartBackfill` for `backfill`.
fn sync_acl(progress: &[u32], backfill: &[u32]) -> Arc<MethodAcl> {
    let callers: std::collections::BTreeSet<u32> =
        progress.iter().chain(backfill).copied().collect();
    let mut text = String::from("[callers]\n");
    for u in &callers {
        text.push_str(&format!("uid-{u} = {u}\n"));
    }
    let names = |uids: &[u32]| {
        uids.iter()
            .map(|u| format!("\"uid-{u}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    text.push_str(&format!(
        "[methods]\n\"{PROGRESS}\" = [{}]\n\"{BACKFILL}\" = [{}]\n",
        names(progress),
        names(backfill)
    ));
    Arc::new(MethodAcl::from_toml(&text, Path::new("cl-sync.toml"), "cl-sync").unwrap())
}

/// Serves the sync service behind `acl` on `listener` until the sender drops.
fn serve_sync(listener: tokio::net::UnixListener, acl: Arc<MethodAcl>) -> oneshot::Sender<()> {
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(
        tonic::transport::Server::builder()
            .layer(AclLayer::new(acl))
            .add_service(SyncServiceServer::new(Sync))
            .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                let _ = rx.await;
            }),
    );
    tx
}

/// The two calls' gRPC codes (`Ok` as `Code::Ok`).
async fn codes(channel: Channel) -> (Code, Code) {
    let mut c = SyncServiceClient::new(channel);
    let progress = c.get_sync_progress(GetSyncProgressRequest::default()).await;
    let backfill = c.start_backfill(StartBackfillRequest::default()).await;
    let code = |r: Result<(), Status>| r.err().map_or(Code::Ok, |s| check_denial(&s));
    (code(progress.map(drop)), code(backfill.map(drop)))
}

fn check_denial(s: &Status) -> Code {
    if s.code() == Code::PermissionDenied {
        assert_eq!(
            ContractError::from_status(s).code(),
            ErrorCode::ContractViolation,
            "{s:?}"
        );
    }
    s.code()
}

/// A channel over an already connected stream (made on another user's thread).
async fn channel_over(stream: std::os::unix::net::UnixStream) -> Channel {
    stream.set_nonblocking(true).unwrap();
    let slot = Arc::new(std::sync::Mutex::new(Some(stream)));
    tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let s = slot.lock().unwrap().take();
            async move {
                let s = s.ok_or_else(|| io::Error::other("one connection only"))?;
                Ok::<_, io::Error>(hyper_util::rt::TokioIo::new(
                    tokio::net::UnixStream::from_std(s)?,
                ))
            }
        }))
        .await
        .unwrap()
}

// ---- counterfeit_server_refused ---------------------------------------------------------------

/// What a server on `listener` read from its first connection until the client hung up (at most
/// 24 bytes: the HTTP/2 preface).
fn first_bytes(listener: tokio::net::UnixListener) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut preface = (&mut s).take(24);
        let read = preface.read_to_end(&mut buf);
        tokio::time::timeout(Duration::from_secs(10), read)
            .await
            .expect("client neither wrote nor hung up")
            .unwrap();
        buf
    })
}

fn wrong_uid(err: &tonic::transport::Error) -> (u32, u32) {
    match uds::peer_refusal(err) {
        Some(PeerCredError::WrongUid { expected, actual }) => (*expected, *actual),
        other => panic!("not refused by the peer check: {other:?} ({err:?})"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn counterfeit_server_refused() {
    let root = runtime_root();
    // A counterfeit cl-verify on the path: it runs as us, the client expects another user.
    let path = root.path().join("counterfeit.sock");
    let read = first_bytes(tokio::net::UnixListener::bind(&path).unwrap());
    let err = uds::connect_path(&path, not_me()).await.unwrap_err();
    assert_eq!(wrong_uid(&err), (not_me(), me()));
    assert_eq!(
        read.await.unwrap(),
        b"",
        "nothing was sent to the counterfeit"
    );

    // Control: expecting our own UID, the same kind of server gets the HTTP/2 preface.
    let path = root.path().join("genuine.sock");
    let read = first_bytes(tokio::net::UnixListener::bind(&path).unwrap());
    let _channel = uds::connect_path(&path, me()).await.unwrap();
    assert!(read.await.unwrap().starts_with(b"PRI * HTTP/2.0"));

    // And through a service socket directory.
    let dir = SocketDir::under(root.path(), "cl-verify").unwrap();
    let (listener, _guard) = uds::bind(&dir, Ownership::current())
        .unwrap()
        .into_tokio()
        .unwrap();
    let read = first_bytes(listener);
    let err = uds::connect(&dir, not_me()).await.unwrap_err();
    assert_eq!(wrong_uid(&err), (not_me(), me()));
    assert_eq!(read.await.unwrap(), b"");

    let Some(u) = users("counterfeit_server_refused") else {
        return;
    };
    // A counterfeit run by another user on a path the client trusts.
    let other_dir = dir_for(root.path(), "other", u.other);
    let path = other_dir.join("cl-verify.sock");
    let counterfeit = as_user(u.other, &[u.other.1], move || std_listener(path));
    let read = first_bytes(tokio::net::UnixListener::from_std(counterfeit).unwrap());
    let path = other_dir.join("cl-verify.sock");
    let err = uds::connect_path(&path, u.chain.0).await.unwrap_err();
    assert_eq!(wrong_uid(&err), (u.chain.0, u.other.0));
    assert_eq!(read.await.unwrap(), b"");
    // The genuine server, run by the expected user, is accepted.
    let chain_dir = dir_for(root.path(), "chain", u.chain);
    let path = chain_dir.join("cl-verify.sock");
    let genuine = as_user(u.chain, &[u.chain.1], move || std_listener(path));
    let read = first_bytes(tokio::net::UnixListener::from_std(genuine).unwrap());
    let _channel = uds::connect_path(chain_dir.join("cl-verify.sock"), u.chain.0)
        .await
        .unwrap();
    assert!(read.await.unwrap().starts_with(b"PRI * HTTP/2.0"));
}

// ---- wrong_uid_caller_refused -------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn wrong_uid_caller_refused() {
    let root = runtime_root();
    let dir = SocketDir::under(root.path(), "cl-sync").unwrap();
    let (listener, _guard) = uds::bind(&dir, Ownership::current())
        .unwrap()
        .into_tokio()
        .unwrap();
    // We may call GetSyncProgress; StartBackfill belongs to another UID.
    let _stop = serve_sync(listener, sync_acl(&[me()], &[not_me()]));
    let channel = uds::connect(&dir, me()).await.unwrap();
    assert_eq!(codes(channel).await, (Code::Ok, Code::PermissionDenied));

    // No Unix credentials at all (TCP): every method is refused.
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .layer(AclLayer::new(sync_acl(&[me()], &[me()])))
            .add_service(SyncServiceServer::new(Sync))
            .serve_with_incoming(TcpListenerStream::new(tcp)),
    );
    let channel = Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    assert_eq!(
        codes(channel).await,
        (Code::PermissionDenied, Code::PermissionDenied)
    );

    let Some(u) = users("wrong_uid_caller_refused") else {
        return;
    };
    // Socket group = the callers' group (api's group here); chain and api are both in it.
    set_mode(root.path(), 0o755);
    let group = u.api.1;
    let dir = SocketDir::under(root.path(), "cl-sync-root").unwrap();
    let (listener, _guard) = uds::bind(&dir, Ownership { uid: 0, gid: group })
        .unwrap()
        .into_tokio()
        .unwrap();
    let _stop = serve_sync(listener, sync_acl(&[u.chain.0, u.api.0], &[u.chain.0]));
    let connect_as = |user: (u32, u32), groups: Vec<u32>| {
        let path = dir.socket_path();
        as_user(user, &groups, move || {
            std::os::unix::net::UnixStream::connect(path)
        })
    };
    let chain = connect_as(u.chain, vec![u.chain.1, group]).unwrap();
    assert_eq!(codes(channel_over(chain).await).await, (Code::Ok, Code::Ok));
    // api may connect (it is in the group) but is not allowed on StartBackfill.
    let api = connect_as(u.api, vec![u.api.1]).unwrap();
    assert_eq!(
        codes(channel_over(api).await).await,
        (Code::Ok, Code::PermissionDenied)
    );
    // other is not in the group: the 0750 directory keeps it off the socket entirely.
    let other = connect_as(u.other, vec![u.other.1]).unwrap_err();
    assert_eq!(other.kind(), io::ErrorKind::PermissionDenied, "{other}");
}

// ---- socket_path_symlink_refused ------------------------------------------------------------

/// A service directory with the right mode, made by hand (as systemd's RuntimeDirectory would).
fn premade_dir(dir: &SocketDir) {
    std::fs::create_dir(dir.dir()).unwrap();
    set_mode(&dir.dir(), 0o750);
}

#[tokio::test(flavor = "multi_thread")]
async fn socket_path_symlink_refused() {
    let root = runtime_root();
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    set_mode(&elsewhere, 0o750);

    // The service directory is a symlink to a directory that would pass every check.
    let dir = SocketDir::under(root.path(), "linked").unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.dir()).unwrap();
    let err = uds::bind(&dir, Ownership::current()).unwrap_err();
    assert!(
        matches!(&err, BindError::Insecure { reason, .. } if reason.contains("symlink")),
        "{err}"
    );
    assert_eq!(
        std::fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "nothing created through it"
    );

    // The socket path is a symlink (to a live socket elsewhere, and to a file).
    let target_sock = elsewhere.join("real.sock");
    let _live = std::os::unix::net::UnixListener::bind(&target_sock).unwrap();
    let target_file = elsewhere.join("file");
    std::fs::write(&target_file, b"keep").unwrap();
    for (name, target) in [("to-socket", &target_sock), ("to-file", &target_file)] {
        let dir = SocketDir::under(root.path(), name).unwrap();
        premade_dir(&dir);
        std::os::unix::fs::symlink(target, dir.socket_path()).unwrap();
        let err = uds::bind(&dir, Ownership::current()).unwrap_err();
        assert!(
            matches!(
                err,
                BindError::NotASocket {
                    kind: "symlink",
                    ..
                }
            ),
            "{name}: {err}"
        );
        assert!(std::fs::symlink_metadata(dir.socket_path())
            .unwrap()
            .file_type()
            .is_symlink());
    }
    assert!(target_sock.exists());
    assert_eq!(std::fs::read(&target_file).unwrap(), b"keep");

    // A regular file or a directory at the socket path is left alone too.
    let dir = SocketDir::under(root.path(), "file").unwrap();
    premade_dir(&dir);
    std::fs::write(dir.socket_path(), b"data").unwrap();
    let err = uds::bind(&dir, Ownership::current()).unwrap_err();
    assert!(
        matches!(
            err,
            BindError::NotASocket {
                kind: "regular file",
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(std::fs::read(dir.socket_path()).unwrap(), b"data");

    // The lock file is a symlink.
    let dir = SocketDir::under(root.path(), "lock").unwrap();
    premade_dir(&dir);
    std::os::unix::fs::symlink(&target_file, dir.lock_path()).unwrap();
    let err = uds::bind(&dir, Ownership::current()).unwrap_err();
    assert!(
        matches!(
            err,
            BindError::NotASocket {
                kind: "symlink",
                ..
            }
        ),
        "{err}"
    );

    // The runtime root itself is a symlink.
    let link = root.path().join("root-link");
    std::os::unix::fs::symlink(root.path(), &link).unwrap();
    let err = uds::bind(
        &SocketDir::under(&link, "svc").unwrap(),
        Ownership::current(),
    )
    .unwrap_err();
    assert!(matches!(err, BindError::Insecure { .. }), "{err}");

    // The socket path is replaced while we serve: shutdown leaves the replacement alone.
    let dir = SocketDir::under(root.path(), "replaced").unwrap();
    let bound = uds::bind(&dir, Ownership::current()).unwrap();
    let staged = dir.dir().join("staged.sock");
    let _replacement = std::os::unix::net::UnixListener::bind(&staged).unwrap();
    std::fs::rename(&staged, dir.socket_path()).unwrap();
    let replacement_ino = std::fs::symlink_metadata(dir.socket_path()).unwrap().ino();
    drop(bound);
    assert_eq!(
        std::fs::symlink_metadata(dir.socket_path()).unwrap().ino(),
        replacement_ino,
        "the replacement is not ours to remove"
    );
}

// ---- stale_socket_cleanup_own_only ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn stale_socket_cleanup_own_only() {
    let root = runtime_root();
    let dir = SocketDir::under(root.path(), "cl-store").unwrap();
    premade_dir(&dir);

    // A socket left by a crashed run of ours: removed, and the new one serves.
    drop(std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap());
    assert!(std::fs::symlink_metadata(dir.socket_path()).is_ok());
    let bound = uds::bind(&dir, Ownership::current()).unwrap();
    let (listener, guard) = bound.into_parts();
    std::os::unix::net::UnixStream::connect(dir.socket_path()).unwrap();

    // A second instance while the first runs: the lock refuses it, the socket stays.
    let err = uds::bind(&dir, Ownership::current()).unwrap_err();
    assert!(
        matches!(&err, BindError::InUse { reason, .. } if reason.contains("lock")),
        "{err}"
    );
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    std::os::unix::net::UnixStream::connect(dir.socket_path()).unwrap();

    // Shutdown begins: the path goes at once, the lock stays until the guard drops.
    let mut guard = guard;
    guard.unlink();
    assert!(std::fs::symlink_metadata(dir.socket_path()).is_err());
    let err = uds::bind(&dir, Ownership::current()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
    // Exit releases the lock; the lock file stays.
    drop((listener, guard));
    assert!(std::fs::symlink_metadata(dir.socket_path()).is_err());
    assert!(dir.lock_path().exists());

    // A live socket that holds no lock (e.g. started by hand): never unlinked.
    let live = std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap();
    let err = uds::bind(&dir, Ownership::current()).unwrap_err();
    assert!(
        matches!(&err, BindError::InUse { reason, .. } if reason.contains("answers")),
        "{err}"
    );
    std::os::unix::net::UnixStream::connect(dir.socket_path()).unwrap();
    drop(live);

    // Now stale: cleaned up.
    let again = uds::bind(&dir, Ownership::current()).unwrap();
    assert_eq!(again.path(), dir.socket_path());
    drop(again);

    let Some(u) = users("stale_socket_cleanup_own_only") else {
        return;
    };
    // A stale or live socket of another user is not ours to remove.
    for live in [false, true] {
        let listener = std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap();
        std::os::unix::fs::lchown(dir.socket_path(), Some(u.other.0), Some(u.other.1)).unwrap();
        let keep = live.then_some(listener);
        let err = uds::bind(&dir, Ownership::current()).unwrap_err();
        assert!(
            matches!(err, BindError::ForeignSocket { owner, .. } if owner == u.other.0),
            "live {live}: {err}"
        );
        let meta = std::fs::symlink_metadata(dir.socket_path()).unwrap();
        assert_eq!(meta.uid(), u.other.0, "left in place");
        drop(keep);
        std::fs::remove_file(dir.socket_path()).unwrap();
    }
}

// ---- bind_modes -----------------------------------------------------------------------------

fn assert_owned(path: &Path, uid: u32, gid: u32, mode: u32) {
    let m = std::fs::symlink_metadata(path).unwrap();
    assert_eq!(
        (m.uid(), m.gid(), m.mode() & 0o7777),
        (uid, gid, mode),
        "{}",
        path.display()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bind_modes() {
    let root = runtime_root();
    // The caller group is set explicitly; prefer one that is not our default group.
    let group = second_group().unwrap_or_else(effective_gid);
    let owner = Ownership {
        uid: me(),
        gid: group,
    };
    let dir = SocketDir::under(root.path(), "cl-engine").unwrap();
    let bound = uds::bind(&dir, owner).unwrap();
    assert_owned(&dir.dir(), me(), group, 0o750);
    assert_owned(&dir.socket_path(), me(), group, 0o660);
    assert!(std::fs::symlink_metadata(dir.socket_path())
        .unwrap()
        .file_type()
        .is_socket());
    drop(bound);
    // The existing directory is accepted as is on the next start.
    drop(uds::bind(&dir, owner).unwrap());

    // A pre-existing directory with any other mode is refused and left unchanged.
    for mode in [0o755, 0o770, 0o751, 0o700, 0o2750] {
        let dir = SocketDir::under(root.path(), &format!("m{mode:o}")).unwrap();
        std::fs::create_dir(dir.dir()).unwrap();
        set_mode(&dir.dir(), mode);
        let err = uds::bind(&dir, Ownership::current()).unwrap_err();
        assert!(matches!(err, BindError::Insecure { .. }), "{mode:o}: {err}");
        assert_eq!(mode_of(&dir.dir()), mode, "not repaired");
        assert!(!dir.socket_path().exists());
    }
    // Another owner (configured: the service user is not us) or another group.
    let err = uds::bind(
        &dir,
        Ownership {
            uid: not_me(),
            gid: group,
        },
    )
    .unwrap_err();
    assert!(matches!(err, BindError::Insecure { .. }), "{err}");
    if let Some(g) = second_group() {
        let err = uds::bind(
            &dir,
            Ownership {
                uid: me(),
                gid: if g == group { effective_gid() } else { g },
            },
        )
        .unwrap_err();
        assert!(matches!(err, BindError::Insecure { .. }), "{err}");
    } else {
        eprintln!("bind_modes: no second group; the wrong-group case runs in the root-tests job");
    }
    // A runtime root others can write to is refused.
    let loose = root.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    set_mode(&loose, 0o777);
    let err = uds::bind(
        &SocketDir::under(&loose, "svc").unwrap(),
        Ownership::current(),
    )
    .unwrap_err();
    assert!(matches!(err, BindError::Insecure { .. }), "{err}");

    let Some(u) = users("bind_modes") else {
        return;
    };
    // As root, bind for the service user and its caller group.
    let owner = Ownership {
        uid: u.chain.0,
        gid: u.api.1,
    };
    let dir = SocketDir::under(root.path(), "as-chain").unwrap();
    let bound = uds::bind(&dir, owner).unwrap();
    assert_owned(&dir.dir(), u.chain.0, u.api.1, 0o750);
    assert_owned(&dir.socket_path(), u.chain.0, u.api.1, 0o660);
    drop(bound);
    // A directory of another owner or group is refused.
    let dir = SocketDir::under(root.path(), "foreign").unwrap();
    premade_dir(&dir);
    std::os::unix::fs::chown(dir.dir(), Some(u.other.0), Some(u.other.1)).unwrap();
    for owner in [
        Ownership {
            uid: 0,
            gid: u.other.1,
        },
        Ownership {
            uid: u.other.0,
            gid: u.api.1,
        },
    ] {
        let err = uds::bind(&dir, owner).unwrap_err();
        assert!(
            matches!(err, BindError::Insecure { .. }),
            "{owner:?}: {err}"
        );
    }
    assert_owned(&dir.dir(), u.other.0, u.other.1, 0o750);
}

// ---- the instance lock and the runtime root's parents -------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn lock_file_owner_and_mode_enforced() {
    let root = runtime_root();
    let group = second_group().unwrap_or_else(effective_gid);
    let owner = Ownership {
        uid: me(),
        gid: group,
    };
    // A lock left with a loose mode (umask, an old run, a hand edit) is reset to 0600 in place.
    for loose in [0o644, 0o660, 0o666, 0o640] {
        let dir = SocketDir::under(root.path(), &format!("l{loose:o}")).unwrap();
        premade_dir(&dir);
        if group != effective_gid() {
            std::os::unix::fs::chown(dir.dir(), None, Some(group)).unwrap();
        }
        std::fs::write(dir.lock_path(), b"").unwrap();
        set_mode(&dir.lock_path(), loose);
        let ino = std::fs::metadata(dir.lock_path()).unwrap().ino();
        let bound = uds::bind(&dir, owner).unwrap();
        assert_owned(&dir.lock_path(), me(), group, 0o600);
        assert_eq!(
            std::fs::metadata(dir.lock_path()).unwrap().ino(),
            ino,
            "same inode"
        );
        drop(bound);
    }
    // A lock even we cannot open is refused, naming its owner and mode.
    let dir = SocketDir::under(root.path(), "closed").unwrap();
    premade_dir(&dir);
    std::fs::write(dir.lock_path(), b"").unwrap();
    set_mode(&dir.lock_path(), 0o000);
    if me() != 0 {
        let err = uds::bind(&dir, Ownership::current()).unwrap_err();
        assert!(err.to_string().contains("cannot open the lock"), "{err}");
    }
    // A fresh lock is 0600 whatever the umask allowed.
    let dir = SocketDir::under(root.path(), "fresh").unwrap();
    drop(uds::bind(&dir, owner).unwrap());
    assert_owned(&dir.lock_path(), me(), group, 0o600);

    let Some(u) = users("lock_file_owner_and_mode_enforced") else {
        return;
    };
    // A lock root created for the service: a restart as the service user is refused with a
    // clear error instead of hanging or taking over.
    let dir = SocketDir::under(root.path(), "root-lock").unwrap();
    set_mode(root.path(), 0o755);
    std::fs::create_dir(dir.dir()).unwrap();
    std::os::unix::fs::chown(dir.dir(), Some(u.chain.0), Some(u.api.1)).unwrap();
    set_mode(&dir.dir(), 0o750);
    std::fs::write(dir.lock_path(), b"").unwrap();
    set_mode(&dir.lock_path(), 0o600);
    let owner = Ownership {
        uid: u.chain.0,
        gid: u.api.1,
    };
    let d = dir.clone();
    let err = as_user(u.chain, &[u.chain.1, u.api.1], move || {
        uds::bind(&d, owner).map(drop).unwrap_err().to_string()
    });
    assert!(err.contains("lock"), "{err}");
    assert_owned(&dir.lock_path(), 0, 0, 0o600);
    // Root, starting for the service user, takes the lock over for it.
    drop(uds::bind(&dir, owner).unwrap());
    assert_owned(&dir.lock_path(), u.chain.0, u.api.1, 0o600);
    // A group-readable lock of another user (a caller could hold its flock) is not trusted.
    std::os::unix::fs::chown(dir.lock_path(), Some(u.other.0), Some(u.other.1)).unwrap();
    set_mode(&dir.lock_path(), 0o660);
    let d = dir.clone();
    let err = as_user(u.chain, &[u.chain.1, u.api.1], move || {
        uds::bind(&d, owner).map(drop).unwrap_err().to_string()
    });
    assert!(err.contains("lock"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn root_with_a_writable_parent_refused() {
    let tmp = runtime_root();
    // Anyone may rename or replace entries in a world-writable parent without the sticky bit.
    let loose = tmp.path().join("loose");
    std::fs::create_dir(&loose).unwrap();
    set_mode(&loose, 0o777);
    let root = loose.join("run");
    std::fs::create_dir(&root).unwrap();
    set_mode(&root, 0o755);
    let err = uds::bind(
        &SocketDir::under(&root, "svc").unwrap(),
        Ownership::current(),
    )
    .unwrap_err();
    assert!(
        matches!(&err, BindError::Insecure { reason, .. } if reason.contains("parent")),
        "{err}"
    );
    assert!(!root.join("svc").exists(), "nothing created under it");
    // A group-writable parent too.
    set_mode(&loose, 0o775);
    assert!(uds::bind(
        &SocketDir::under(&root, "svc").unwrap(),
        Ownership::current()
    )
    .is_err());
    // The sticky bit (as on /tmp) makes a world-writable parent acceptable.
    set_mode(&loose, 0o1777);
    drop(
        uds::bind(
            &SocketDir::under(&root, "svc").unwrap(),
            Ownership::current(),
        )
        .unwrap(),
    );
}
