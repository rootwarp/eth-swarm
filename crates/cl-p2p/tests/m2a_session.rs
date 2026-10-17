//! `m2a-session` log hygiene: no node-key material in any log line.
//!
//! This is its own test binary with a single test, on purpose. `tracing` caches each callsite's
//! interest process-wide. A thread-scoped subscriber (`set_default`) in a unit test races the
//! other unit tests that hit the same callsites (every `Session::start`) on other threads: a
//! callsite first registered there, concurrently with the scoped subscriber, can be cached as
//! disabled, and the capture then misses its lines. Here the capturing subscriber is the global
//! default, installed before any callsite is hit, in a process where nothing else runs.

mod tests {
    use cl_p2p::m2a_session::{
        preflight, KeySource, PinnedPeer, Preflight, Session, SessionError, Transport,
    };
    use consensus_types::Minimal;
    use futures::StreamExt;
    use libp2p::identity::{secp256k1, Keypair};
    use libp2p::swarm::{dummy, SwarmEvent};
    use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, SwarmBuilder};
    use p2p_wire::rpc::codec::ContextTable;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A valid secp256k1 secret that cannot occur by accident in a log.
    const SECRET: [u8; 32] = [
        0x3c, 0x91, 0x5e, 0x07, 0xd4, 0x22, 0x8b, 0xf6, 0x19, 0xa0, 0x6d, 0x43, 0xe8, 0x75, 0x0b,
        0xc2, 0x57, 0x9e, 0x31, 0x6a, 0xf0, 0x84, 0x2d, 0xbb, 0x48, 0x13, 0xcf, 0x66, 0x09, 0xae,
        0x72, 0x15,
    ];

    /// A `tracing` writer that keeps everything in memory.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A loopback TCP peer with its own identity, serving nothing.
    async fn loopback_peer() -> (PeerId, Multiaddr) {
        let mut swarm = SwarmBuilder::with_existing_identity(Keypair::generate_secp256k1())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| dummy::Behaviour)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let id = *swarm.local_peer_id();
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let addr = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                break address;
            }
        };
        tokio::spawn(async move {
            loop {
                swarm.select_next_some().await;
            }
        });
        (id, addr)
    }

    #[test]
    fn key_never_logged() {
        // First, before any callsite is hit: the one subscriber of this process.
        let log = Captured::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("the only subscriber");

        // The key comes from a 0600 key file with known bytes, through the real pre-flight.
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&SECRET).unwrap();
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        let euid = rustix::process::geteuid().as_raw();
        let key = preflight(&Preflight {
            euid,
            key: KeySource::File(file.path().into()),
        })
        .unwrap();
        let local = key.peer_id();
        let reference = Keypair::from(secp256k1::Keypair::from(
            secp256k1::SecretKey::try_from_bytes(SECRET).unwrap(),
        ));
        assert_eq!(reference.public().to_peer_id(), local);
        let protobuf = reference.to_protobuf_encoding().unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            // A real Noise handshake over loopback, with a peer that is not the pinned one.
            let (_, addr) = loopback_peer().await;
            let pinned = PinnedPeer {
                peer_id: PeerId::random(),
                addr,
            };
            let mut session = Session::<Minimal>::start(
                key,
                pinned,
                Arc::new(ContextTable::new()),
                Transport::Tcp,
            )
            .unwrap();
            // Returns once the dial has failed: every session log line is written by then.
            let err = session.connect().await.unwrap_err();
            assert!(matches!(err, SessionError::Dial { .. }), "{err}");
            drop(session);
        });
        drop(runtime);

        let raw = log.0.lock().unwrap().clone();
        let text = String::from_utf8_lossy(&raw).into_owned();
        // The capture works: the session's own lines, from start and from the failed dial.
        assert!(
            text.contains(&local.to_string()),
            "the peer ID is logged:\n{text}"
        );
        assert!(text.contains("m2a-session starting"), "{text}");
        assert!(text.contains("dial failed"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        let forbidden = [
            ("secret hex", hex(&SECRET)),
            ("secret HEX", hex(&SECRET).to_uppercase()),
            ("secret base58", bs58::encode(SECRET).into_string()),
            ("secret bytes", format!("{SECRET:?}")),
            ("protobuf hex", hex(&protobuf)),
            ("protobuf base58", bs58::encode(&protobuf).into_string()),
            ("protobuf bytes", format!("{protobuf:?}")),
        ];
        for (what, needle) in forbidden {
            assert!(!text.contains(&needle), "{what} in the log");
        }
        assert!(
            !raw.windows(32).any(|w| w == SECRET),
            "raw secret in the log"
        );
    }
}
