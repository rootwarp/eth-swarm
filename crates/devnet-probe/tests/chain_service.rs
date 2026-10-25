//! cl-p2p's clients of cl-chain (`ChainStatus` for `GetStatus`, `ChainColumns` for the column
//! RPCs) over the socket of the cl-chain service, as `cl_chain::service::serve` runs it through
//! svc-runtime: its config (`network_dir`, `[socket]`, `[callers]`, `[methods]`, `[chain]`), its
//! socket under the runtime root, and its method ACL. In process, with a fixture reference API
//! and a KZG verifier that passes every cell.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use cl_chain::probe::service::{chain_link, system_ms, CHAIN_METHODS};
use cl_chain::verify::client::{KzgOutcome, KzgVerifier};
use cl_p2p::rpc::chain_status::ChainStatus;
use cl_p2p::rpc::columns::{ChainColumns, ColumnReply, ColumnSource};
use cl_p2p::rpc::limits::MAX_COLUMN_RESPONSE_BYTES;
use consensus_types::Minimal;
use devnet_probe::fixtures::FixtureChain;
use ethswarm_proto::chain as pb;
use ethswarm_proto::verify::KzgCellProof;
use ipc::testkit::devnet::{devnet_genesis_state, write_network_file, KURTOSIS_CONFIG};
use p2p_wire::rpc::messages::{
    DataColumnsByRangeV1Request, DataColumnsByRootIdentifier, DataColumnsByRootV1Request,
};
use p2p_wire::rpc::protocols::ResultCode;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use svc_runtime::notify::Notifier;
use svc_runtime::{Config, Hooks};
use tokio::sync::{mpsc, oneshot};

/// Passes every cell.
struct Valid;

impl KzgVerifier for Valid {
    async fn verify_cells(&self, _: Vec<KzgCellProof>, _: Duration) -> KzgOutcome {
        KzgOutcome::Valid
    }
}

/// A service manager that hands every notification to the test.
struct Recorder(mpsc::UnboundedSender<String>);

impl Notifier for Recorder {
    fn notify(&self, state: &str) -> std::io::Result<()> {
        let _ = self.0.send(state.to_owned());
        Ok(())
    }
}

fn mkdir(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The cl-chain config of a service on `root`, the reference at `reference`.
fn config_text(root: &Path, reference: &str) -> String {
    let current = ipc::uds::Ownership::current();
    let mut text = format!(
        "network_dir = \"{}\"\nmetrics_port = 9102\n\n[socket]\nroot = \"{}\"\ngroup = {}\n\n\
         [callers]\ncl-p2p = {}\n\n[methods]\n",
        root.join("network").display(),
        root.join("run").display(),
        current.gid,
        current.uid
    );
    for m in CHAIN_METHODS {
        text.push_str(&format!("\"{m}\" = [\"cl-p2p\"]\n"));
    }
    text.push_str(&format!(
        "\n[chain]\nreference_api_url = \"http://{reference}\"\nnode_id = \"0x{}07\"\n\
         verify_socket = \"/run/ethswarm/cl-verify/cl-verify.sock\"\nverify_uid = {}\n\
         columns_dir = \"{}\"\n",
        "00".repeat(31),
        current.uid,
        root.join("state/columns").display()
    ));
    text
}

#[tokio::test(flavor = "multi_thread")]
async fn cl_p2p_reads_status_and_columns_from_the_chain_service() {
    // The reference: finalized at epoch 10, block slot 80.
    let reference = FixtureChain::default();
    reference.finalize(10, [0x11; 32].into(), 80);
    let api = reference.serve().await;

    let dir = tempfile::Builder::new()
        .tempdir_in(svc_runtime::owned::testkit::config_root())
        .unwrap();
    let root = dir.path();
    mkdir(&root.join("network"), 0o755);
    let yaml = format!("{KURTOSIS_CONFIG}MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS: 4096\n");
    write_network_file(root.join("network/config.yaml"), &yaml);
    write_network_file(root.join("network/genesis.ssz"), devnet_genesis_state(64));
    mkdir(&root.join("run"), 0o755);
    mkdir(&root.join("state"), 0o700);
    let text = config_text(root, &api.addr.to_string());
    let config = Config::from_toml("cl-chain", &text, Path::new("cl-chain.toml"))
        .unwrap()
        .with_ephemeral_metrics_port();
    let socket = config.socket.socket_path();
    let settings = cl_chain::service::settings(&config).unwrap();
    let net = settings.network.clone();
    let started_slot = net.slot_at(system_ms()).unwrap();

    let (tx, mut states) = mpsc::unbounded_channel();
    let (stop, stopped) = oneshot::channel::<()>();
    let hooks = Hooks {
        notifier: Arc::new(Recorder(tx)),
        shutdown: Box::pin(async {
            let _ = stopped.await;
        }),
        registry: prometheus_client::registry::Registry::with_prefix("ethswarm"),
        unprefixed: prometheus_client::registry::Registry::default(),
    };
    let served = tokio::spawn(async move {
        cl_chain::service::serve::<Minimal, _>(config, &settings, Valid, hooks).await
    });
    let ready = tokio::time::timeout(Duration::from_secs(30), states.recv())
        .await
        .expect("READY in time")
        .expect("READY");
    assert!(ready.starts_with("READY=1"), "{ready}");

    let uid = ipc::uds::Ownership::current().uid;
    let channel = ipc::uds::connect_path(&socket, uid).await.unwrap();

    // GetStatus: the reference's finalized checkpoint and block, the wall clock's digest, and
    // the slot the store serves from: the slot custody was set at, nothing being stored yet.
    let status = ChainStatus::new(channel.clone()).status().await.unwrap();
    assert_eq!(status.finalized_epoch, 10);
    assert_eq!(status.finalized_root.0, [0x11; 32]);
    assert_eq!(status.head_slot, 80);
    let epoch = net.epoch_at(system_ms()).unwrap();
    assert_eq!(status.fork_digest, net.digest_at(epoch).unwrap());
    assert!(status.earliest_available_slot >= started_slot);

    // The column RPCs, through the chain.v1 contract layer: nothing stored, so a custody
    // column by range is `3: ResourceUnavailable`, never an empty success.
    let link = chain_link::<Minimal>(&net, system_ms()).unwrap();
    let columns = ChainColumns::new(channel.clone(), link, MAX_COLUMN_RESPONSE_BYTES);
    let custody =
        consensus_types::das::custody_columns(consensus_types::primitives::U256::from(7u64), 4)
            .unwrap();
    let range = DataColumnsByRangeV1Request {
        start_slot: started_slot,
        count: 1,
        columns: custody.clone().try_into().unwrap(),
    };
    match columns.by_range(&range).await {
        ColumnReply::Refused(code, _) => assert_eq!(code, ResultCode::ResourceUnavailable),
        other => panic!("refused, got {other:?}"),
    }
    let root_request = DataColumnsByRootV1Request(
        vec![DataColumnsByRootIdentifier {
            block_root: [0x22; 32].into(),
            columns: custody.try_into().unwrap(),
        }]
        .try_into()
        .unwrap(),
    );
    match columns.by_root(&root_request).await {
        ColumnReply::Refused(code, _) => assert_eq!(code, ResultCode::ResourceUnavailable),
        ColumnReply::Sidecars(got) => assert!(got.is_empty()),
    }

    // A method outside the ACL is denied before it is decoded, whoever calls it.
    let denied = pb::req_resp_service_client::ReqRespServiceClient::new(channel)
        .get_metadata(pb::GetMetadataRequest {})
        .await
        .unwrap_err();
    assert_eq!(denied.code(), tonic::Code::PermissionDenied);

    // SIGTERM (the shutdown hook): a clean drain, and the socket is gone.
    stop.send(()).unwrap();
    served.await.unwrap().unwrap();
    assert!(std::fs::symlink_metadata(&socket).is_err());
}
