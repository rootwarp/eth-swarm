//! The method ACL in front of a real service: cl-engine's stub, served by the runtime.
//!
//! A caller that may reach the socket (it owns the directory, or is in the socket group) but is
//! not listed for a method gets `PERMISSION_DENIED`; cl-engine takes only cl-chain. The
//! multi-UID part needs root on Linux (see `tests/common`).

mod common;

use common::*;
use ethswarm_proto::common::ErrorCode;
use ethswarm_proto::engine as pb;
use ethswarm_proto::engine::engine_service_client::EngineServiceClient;
use ipc::acl::AclError;
use ipc::ContractError;
use svc_runtime::config::ConfigError;
use tonic::transport::Channel;
use tonic::Code;

/// The gRPC code of each engine method, in `ENGINE_METHODS` order.
async fn engine_codes(channel: Channel) -> Vec<Code> {
    let mut c = EngineServiceClient::new(channel);
    let code = |r: Result<(), tonic::Status>| match r {
        Ok(()) => Code::Ok,
        Err(s) => {
            if s.code() == Code::PermissionDenied {
                assert_eq!(
                    ContractError::from_status(&s).code(),
                    ErrorCode::ContractViolation
                );
            }
            s.code()
        }
    };
    vec![
        code(
            c.new_payload(pb::NewPayloadRequest::default())
                .await
                .map(drop),
        ),
        code(
            c.forkchoice_updated(pb::ForkchoiceUpdatedRequest::default())
                .await
                .map(drop),
        ),
        code(
            c.get_payload(pb::GetPayloadRequest::default())
                .await
                .map(drop),
        ),
        code(c.get_blobs(pb::GetBlobsRequest::default()).await.map(drop)),
        code(
            c.exchange_capabilities(pb::ExchangeCapabilitiesRequest::default())
                .await
                .map(drop),
        ),
    ]
}

fn engine_routes() -> svc_runtime::Services {
    let stub = cl_engine::EngineStub::new(ipc::testkit::fixture::v1_link());
    svc_runtime::Services::new()
        .add_service(ethswarm_proto::engine::engine_service_server::EngineServiceServer::new(stub))
}

const STUB: Code = Code::Unimplemented; // the stub answers every call it is let through with this

#[tokio::test(flavor = "multi_thread")]
async fn acl_per_method() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let gid = ipc::peercred::effective_gid();
    let only_chain = r#"["cl-chain"]"#;

    // We are cl-chain and every method is listed: every call reaches the service.
    let config = engine_config(
        tmp.path(),
        &engine_toml(&root, gid, me(), &ENGINE_METHODS, only_chain, 5000),
    )
    .unwrap();
    let mut svc = start(config, engine_routes()).await;
    let channel = ipc::uds::connect(&svc.socket, me()).await.unwrap();
    assert_eq!(engine_codes(channel).await, vec![STUB; 5]);
    svc.terminate();
    svc.task.await.unwrap().unwrap();

    // GetBlobs is not listed: denied, the rest served, and the denial is counted.
    let listed: Vec<&str> = ENGINE_METHODS
        .iter()
        .copied()
        .filter(|m| !m.ends_with("/GetBlobs"))
        .collect();
    let config = engine_config(
        tmp.path(),
        &engine_toml(&root, gid, me(), &listed, only_chain, 5000),
    )
    .unwrap();
    let mut svc = start(config, engine_routes()).await;
    let channel = ipc::uds::connect(&svc.socket, me()).await.unwrap();
    assert_eq!(
        engine_codes(channel).await,
        vec![STUB, STUB, STUB, Code::PermissionDenied, STUB]
    );
    let metrics = scrape(svc.metrics).await;
    assert!(metrics.contains("ethswarm_acl_denied_total 1"), "{metrics}");
    svc.terminate();
    svc.task.await.unwrap().unwrap();

    // cl-chain is another UID: we own the socket directory, so we reach the socket, but we are
    // not cl-chain and every method refuses us.
    let config = engine_config(
        tmp.path(),
        &engine_toml(&root, gid, not_me(), &ENGINE_METHODS, only_chain, 5000),
    )
    .unwrap();
    let mut svc = start(config, engine_routes()).await;
    let channel = ipc::uds::connect(&svc.socket, me()).await.unwrap();
    assert_eq!(engine_codes(channel).await, vec![Code::PermissionDenied; 5]);
    svc.terminate();
    svc.task.await.unwrap().unwrap();

    // A second caller, or a caller other than cl-chain, does not load: cl-engine never starts.
    for callers in [r#"["cl-chain", "cl-api"]"#, r#"["cl-api"]"#] {
        let err = engine_config(
            tmp.path(),
            &engine_toml(&root, gid, me(), &ENGINE_METHODS, callers, 5000),
        )
        .unwrap_err();
        assert!(
            matches!(&err, ConfigError::Acl(e) if matches!(**e, AclError::SoleCaller { .. })),
            "{callers}: {err}"
        );
    }

    let Some(u) = users("acl_per_method") else {
        return;
    };
    // As root: cl-chain and cl-api are both in the socket group; only cl-chain gets cl-engine.
    // A fresh root: the directory and lock above belong to root's own group, and an existing
    // one of another group is refused, never repaired.
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let group = u.api.1;
    let text = engine_toml(&root, group, u.chain.0, &ENGINE_METHODS, only_chain, 5000).replace(
        &format!("cl-api = {}", not_me().wrapping_add(1)),
        &format!("cl-api = {}", u.api.0),
    );
    let config = engine_config(tmp.path(), &text).unwrap();
    let mut svc = start(config, engine_routes()).await;
    let path = svc.socket.socket_path();
    let chain = connect_as(u.chain, &[u.chain.1, group], path.clone()).unwrap();
    assert_eq!(engine_codes(channel_over(chain).await).await, vec![STUB; 5]);
    let api = connect_as(u.api, &[u.api.1], path.clone()).unwrap();
    assert_eq!(
        engine_codes(channel_over(api).await).await,
        vec![Code::PermissionDenied; 5]
    );
    let other = connect_as(u.other, &[u.other.1], path).unwrap_err();
    assert_eq!(
        other.kind(),
        std::io::ErrorKind::PermissionDenied,
        "{other}"
    );
    svc.terminate();
    svc.task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn acl_method_not_served_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = runtime_root(tmp.path());
    let gid = ipc::peercred::effective_gid();
    // A misspelled method would stay denied forever; the runtime refuses to start instead.
    let typo = "/ethswarm.engine.v1.EngineService/NewPaylod";
    let methods = [ENGINE_METHODS[1], typo];
    let config = engine_config(
        tmp.path(),
        &engine_toml(&root, gid, me(), &methods, r#"["cl-chain"]"#, 1000),
    )
    .unwrap();
    let socket = config.socket.socket_path();
    let hooks = svc_runtime::Hooks {
        notifier: std::sync::Arc::new(Recorder::default()),
        shutdown: Box::pin(std::future::pending()),
        registry: prometheus_client::registry::Registry::default(),
        unprefixed: prometheus_client::registry::Registry::default(),
    };
    let err = svc_runtime::run_with(config, engine_routes(), hooks)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, svc_runtime::RuntimeError::UnservedMethods(p) if p == &[typo.to_owned()]),
        "{err}"
    );
    assert!(err.to_string().contains(typo), "{err}");
    assert!(!socket.exists(), "nothing bound");
}
