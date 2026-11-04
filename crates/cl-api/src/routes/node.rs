//! `/eth/v1/node/{health,syncing,version}` (beacon-APIs `01e99a6` `apis/node/`).
//!
//! - `health` answers with a status code only. It returns 200 when ready, 206 when syncing,
//!   optimistic, the engine offline or cl-chain unreachable, and 503 before the first chain
//!   status ([`Health`](crate::node_state::Health)). `?syncing_status=<100..=599>` replaces the
//!   206. A value outside that range is 400, whatever the state.
//! - `syncing` reports [`NodeState::syncing`](crate::node_state::NodeState::syncing), with the
//!   slots as decimal strings.
//! - `version` reads `ethswarm/<semver>/<arch>-<os>` ([`version_string`]).

use axum::Router;

use crate::server::ApiState;

/// The node routes.
pub fn routes() -> Router<ApiState> {
    todo!()
}

/// `ethswarm/<crate version>/<arch>-<os>`, e.g. `ethswarm/0.1.0/x86_64-linux`.
#[must_use]
pub fn version_string() -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ethswarm_proto::chain::import_service_client::ImportServiceClient;
    use http::StatusCode;
    use ipc::testkit::{Mode, Server};

    use crate::node_state::{poll_once, ChainHead, Health, NodeState};
    use crate::server::router;
    use crate::testing::{self, get, json, sync_status, FakeChain, WALL_SLOT};

    const HEALTH: &str = "/eth/v1/node/health";
    const SYNCING: &str = "/eth/v1/node/syncing";
    const CALL: Duration = Duration::from_secs(5);

    fn head(head_slot: u64, optimistic: bool, el_offline: bool) -> ChainHead {
        ChainHead {
            head_slot,
            optimistic,
            el_offline,
        }
    }

    async fn status(app: &axum::Router, uri: &str) -> StatusCode {
        let (status, _, body) = get(app, uri).await;
        if status.is_success() {
            assert!(body.is_empty(), "health has no body: {body:?}");
        }
        status
    }

    async fn syncing(app: &axum::Router) -> serde_json::Value {
        let (status, _, body) = get(app, SYNCING).await;
        assert_eq!(status, StatusCode::OK);
        json(&body)["data"].clone()
    }

    #[tokio::test]
    async fn health_codes() {
        let node = NodeState::new(testing::clock());
        let app = router(testing::api_state(node.clone()));
        // Not initialised: no chain status yet.
        assert_eq!(node.health(), Health::NotInitialised);
        assert_eq!(status(&app, HEALTH).await, StatusCode::SERVICE_UNAVAILABLE);
        let cases = [
            (head(WALL_SLOT, false, false), Health::Ready, StatusCode::OK),
            // At the tolerance it is still synced; one slot more is syncing.
            (
                head(WALL_SLOT - 8, false, false),
                Health::Ready,
                StatusCode::OK,
            ),
            (
                head(WALL_SLOT - 9, false, false),
                Health::Degraded,
                StatusCode::PARTIAL_CONTENT,
            ),
            (
                head(WALL_SLOT, true, false),
                Health::Degraded,
                StatusCode::PARTIAL_CONTENT,
            ),
            (
                head(WALL_SLOT, false, true),
                Health::Degraded,
                StatusCode::PARTIAL_CONTENT,
            ),
            (
                head(0, true, true),
                Health::Degraded,
                StatusCode::PARTIAL_CONTENT,
            ),
            (head(WALL_SLOT, false, false), Health::Ready, StatusCode::OK),
        ];
        for (head, health, code) in cases {
            node.record_head(head);
            assert_eq!(node.health(), health, "{head:?}");
            assert_eq!(status(&app, HEALTH).await, code, "{head:?}");
        }
        // cl-chain unreachable after a status: 206, not 503.
        node.record_unreachable();
        assert_eq!(node.health(), Health::Degraded);
        assert_eq!(status(&app, HEALTH).await, StatusCode::PARTIAL_CONTENT);
    }

    #[tokio::test]
    async fn syncing_status_override() {
        let node = NodeState::new(testing::clock());
        let app = router(testing::api_state(node.clone()));
        let at = |query: &str| format!("{HEALTH}{query}");
        // While syncing: the parameter replaces 206.
        node.record_head(head(WALL_SLOT - 100, false, false));
        assert_eq!(status(&app, HEALTH).await, StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            status(&app, &at("?syncing_status=200")).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&app, &at("?syncing_status=503")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(status(&app, &at("?syncing_status=100")).await.as_u16(), 100);
        assert_eq!(status(&app, &at("?syncing_status=599")).await.as_u16(), 599);
        // Other parameters are ignored.
        assert_eq!(
            status(&app, &at("?other=1&syncing_status=200")).await,
            StatusCode::OK
        );
        // An invalid value: 400, with the error body.
        for bad in [
            "x",
            "",
            "99",
            "600",
            "-1",
            "200.0",
            "2000000000000",
            "200&syncing_status=200",
        ] {
            let (code, _, body) = get(&app, &at(&format!("?syncing_status={bad}"))).await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{bad:?}");
            assert_eq!(json(&body)["code"], 400, "{bad:?}");
        }
        // Ready: the parameter does not apply, but is still checked.
        node.record_head(head(WALL_SLOT, false, false));
        assert_eq!(
            status(&app, &at("?syncing_status=299")).await,
            StatusCode::OK
        );
        assert_eq!(
            status(&app, &at("?syncing_status=abc")).await,
            StatusCode::BAD_REQUEST
        );
        // Not initialised stays 503.
        let fresh = router(testing::api_state(NodeState::new(testing::clock())));
        assert_eq!(
            status(&fresh, &at("?syncing_status=200")).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn el_offline() {
        // The engine offline, as cl-chain reports it with the mock EL down.
        let chain = FakeChain::new(sync_status(WALL_SLOT, false, true));
        let connection = Mode::InProcess.connect(Server::new(chain.routes())).await;
        let mut client = ImportServiceClient::new(connection.transport.clone());
        let node = NodeState::new(testing::clock());
        let app = router(testing::api_state(node.clone()));
        poll_once(&mut client, &node, CALL).await;
        assert!(node.chain_reachable());
        let data = syncing(&app).await;
        assert_eq!(data["el_offline"], true);
        assert_eq!(data["is_syncing"], false);
        assert_eq!(data["is_optimistic"], false);
        assert_eq!(data["head_slot"], WALL_SLOT.to_string());
        assert_eq!(data["sync_distance"], "0");
        assert_eq!(status(&app, HEALTH).await, StatusCode::PARTIAL_CONTENT);
        // The engine is back.
        chain.set(sync_status(WALL_SLOT, false, false));
        poll_once(&mut client, &node, CALL).await;
        assert_eq!(syncing(&app).await["el_offline"], false);
        assert_eq!(status(&app, HEALTH).await, StatusCode::OK);
        // Optimistic comes through the same status.
        chain.set(sync_status(WALL_SLOT, true, false));
        poll_once(&mut client, &node, CALL).await;
        assert_eq!(syncing(&app).await["is_optimistic"], true);
        assert_eq!(status(&app, HEALTH).await, StatusCode::PARTIAL_CONTENT);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chain_unreachable_syncing() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("cl-chain.sock");
        let chain = FakeChain::new(sync_status(WALL_SLOT - 1, false, false));
        let running = chain.serve_uds(&socket);
        // The binary's connector: it checks the server's UID.
        let channel = ipc::uds::connect_path(&socket, ipc::peercred::effective_uid())
            .await
            .unwrap();
        let mut client = ImportServiceClient::new(channel);
        let node = NodeState::new(testing::clock());
        let app = router(testing::api_state(node.clone()));
        poll_once(&mut client, &node, CALL).await;
        assert_eq!(syncing(&app).await["is_syncing"], false);
        assert_eq!(status(&app, HEALTH).await, StatusCode::OK);

        // cl-chain stops. The next poll, one interval later, finds it gone.
        running.stop().await;
        poll_once(&mut client, &node, CALL).await;
        assert!(!node.chain_reachable());
        let data = syncing(&app).await;
        assert_eq!(data["is_syncing"], true);
        // From the last cached head.
        assert_eq!(data["head_slot"], (WALL_SLOT - 1).to_string());
        assert_eq!(data["sync_distance"], "1");
        assert_eq!(data["is_optimistic"], false);
        assert_eq!(data["el_offline"], false);
        assert_eq!(status(&app, HEALTH).await, StatusCode::PARTIAL_CONTENT);

        // cl-chain is back on the same socket: the next poll clears it.
        chain.set(sync_status(WALL_SLOT, false, false));
        let running = chain.serve_uds(&socket);
        poll_once(&mut client, &node, CALL).await;
        assert!(node.chain_reachable());
        assert_eq!(syncing(&app).await["is_syncing"], false);
        assert_eq!(status(&app, HEALTH).await, StatusCode::OK);
        running.stop().await;

        // A poll that times out counts as unreachable too.
        let hung = FakeChain::new(sync_status(WALL_SLOT, false, false)).hanging();
        let connection = Mode::InProcess.connect(Server::new(hung.routes())).await;
        let mut hung_client = ImportServiceClient::new(connection.transport.clone());
        poll_once(&mut hung_client, &node, Duration::from_millis(50)).await;
        assert!(!node.chain_reachable());
        assert!(node.syncing().is_syncing);
        assert_eq!(node.health(), Health::Degraded);
    }

    #[tokio::test]
    async fn syncing_before_the_first_status() {
        let app = router(testing::api_state(NodeState::new(testing::clock())));
        let data = syncing(&app).await;
        assert_eq!(data["head_slot"], "0");
        assert_eq!(data["sync_distance"], WALL_SLOT.to_string());
        assert_eq!(data["is_syncing"], true);
        assert_eq!(data["is_optimistic"], false);
        assert_eq!(data["el_offline"], false);
    }

    #[tokio::test]
    async fn version() {
        let app = router(testing::api_state(NodeState::new(testing::clock())));
        let (status, _, body) = get(&app, "/eth/v1/node/version").await;
        assert_eq!(status, StatusCode::OK);
        let version = json(&body)["data"]["version"].as_str().unwrap().to_owned();
        assert_eq!(version, super::version_string());
        let parts: Vec<&str> = version.split('/').collect();
        assert_eq!(parts.len(), 3, "{version}");
        assert_eq!(parts[0], "ethswarm");
        assert_eq!(parts[1], env!("CARGO_PKG_VERSION"));
        let numbers: Vec<&str> = parts[1]
            .split(['-', '+'])
            .next()
            .unwrap()
            .split('.')
            .collect();
        assert_eq!(numbers.len(), 3, "{version}");
        assert!(
            numbers.iter().all(|n| n.parse::<u64>().is_ok()),
            "{version}"
        );
        assert_eq!(
            parts[2],
            format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
        );
    }
}
