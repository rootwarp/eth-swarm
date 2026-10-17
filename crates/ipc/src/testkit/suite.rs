//! The rules, and the suite that runs them against one service.
//!
//! Each rule is checked in both directions where the package has the surface for it:
//! the service as receiver (a [`Probe`] call against the service), and the service's peers as
//! receiver (the ipc client guard against a scripted server for the same RPC). A rule whose
//! surface the package lacks (no stream, no envelope) asserts that absence from the descriptor
//! set and checks the service's [`Link`] configuration directly, so it fails as soon as the
//! package grows that surface without a probe.

use std::path::Path;
use std::sync::Arc;

use ethswarm_proto::common::{Envelope, ErrorCode, Hello, PayloadType};
use network_config::ForkName;

use super::fixture::{self, digest_at, SLOTS_PER_EPOCH};
use super::probe::{call_unary_empty, Answer, GuardReport, Probe, Step, UnaryProbe};
use super::surface::{surface, Surface};
use super::{Mode, Server};
use crate::acl::{self, AclError, AclTables, MethodAcl};
use crate::envelope::EnvelopeError;
use crate::error::ContractError;
use crate::frame::Frame;
use crate::hello::negotiate;
use crate::link::{Counts, Link};
use crate::peercred::{self, PeerCredError};
use crate::uds::{self, PeerCheckedConnector};

/// Every contract rule of the suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rule {
    /// N/N-1: the link uses `min(max_a, max_b)` and fails below `max(min_a, min_b)`.
    HelloVersionNN1,
    /// A link below the configured floor fails with `ERROR_CODE_VERSION_MISMATCH`.
    HelloFloor,
    /// A spec-pin, fork-schedule or blob-schedule difference fails the link.
    HelloPinMismatch,
    /// Exactly one hello, first, per direction; missing or second is a contract violation.
    HelloOnce,
    /// `Envelope.seq` increases strictly from 1 per direction and is 0 on unary calls.
    SeqMonotonic,
    /// A zero or missing `payload_type` is a contract violation; an unknown one is IGNOREd.
    EnvelopeTypeRules,
    /// A fork digest that does not match the slot's fork is dropped undecoded.
    EnvelopeDigestMismatch,
    /// Unary calls carry no hello and are served without one.
    UnaryNoHello,
    /// Both ends check the Unix-socket peer's UID: the service per method (an unlisted method,
    /// a UID not listed for the method, and a request without credentials are
    /// `PERMISSION_DENIED` before the service sees them; cl-engine and cl-verify take only
    /// cl-chain), and its peers before sending a byte (a server with another UID is refused).
    SoPeercred,
}

impl Rule {
    pub const ALL: [Rule; 9] = [
        Rule::HelloVersionNN1,
        Rule::HelloFloor,
        Rule::HelloPinMismatch,
        Rule::HelloOnce,
        Rule::SeqMonotonic,
        Rule::EnvelopeTypeRules,
        Rule::EnvelopeDigestMismatch,
        Rule::UnaryNoHello,
        Rule::SoPeercred,
    ];

    /// The test name the suite gives the rule.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Rule::HelloVersionNN1 => "hello_version_n_n1",
            Rule::HelloFloor => "hello_floor",
            Rule::HelloPinMismatch => "hello_pin_mismatch",
            Rule::HelloOnce => "hello_once",
            Rule::SeqMonotonic => "seq_monotonic",
            Rule::EnvelopeTypeRules => "envelope_type_rules",
            Rule::EnvelopeDigestMismatch => "envelope_digest_mismatch",
            Rule::UnaryNoHello => "unary_no_hello",
            Rule::SoPeercred => "so_peercred",
        }
    }
}

type Counter = Arc<dyn Fn() -> u64 + Send + Sync>;

/// One service under test, built from the link the suite wants it to use.
#[derive(Clone)]
pub struct Target {
    package: &'static str,
    server: Server,
    link: Link,
    probe: Option<Arc<dyn Probe>>,
    unary: Option<Arc<dyn UnaryProbe>>,
    violations: Counter,
}

impl Target {
    /// `package` (e.g. `ethswarm.store.v1`) served by `server`, configured with `link`.
    #[must_use]
    pub fn new(package: &'static str, server: Server, link: Link) -> Self {
        let l = link.clone();
        Self {
            package,
            server,
            link,
            probe: None,
            unary: None,
            violations: Arc::new(move || l.metrics().counts().contract_violations),
        }
    }

    /// The streaming RPC the hello, seq and envelope rules run on.
    #[must_use]
    pub fn with_probe(mut self, probe: Arc<dyn Probe>) -> Self {
        self.probe = Some(probe);
        self
    }

    /// The unary RPC whose request carries envelopes.
    #[must_use]
    pub fn with_unary_probe(mut self, probe: Arc<dyn UnaryProbe>) -> Self {
        self.unary = Some(probe);
        self
    }

    /// The service's own contract-violation metric, when it does not count through `link`.
    #[must_use]
    pub fn with_violation_counter(
        mut self,
        counter: impl Fn() -> u64 + Send + Sync + 'static,
    ) -> Self {
        self.violations = Arc::new(counter);
        self
    }

    fn counts(&self) -> Counts {
        self.link.metrics().counts()
    }
}

/// Builds the target for a link.
pub type TargetFactory = fn(Link) -> Target;

/// Runs [`Rule`]s against the targets a factory builds.
pub struct ContractSuite {
    factory: TargetFactory,
}

fn code(e: &Option<ContractError>) -> Option<ErrorCode> {
    e.as_ref().map(ContractError::code)
}

/// A service's hello: `expected` in every field but `generation`, which must be a non-zero
/// server generation (README, server generation).
fn assert_server_hello(theirs: &Hello, expected: &Hello, ctx: &str) {
    assert_ne!(theirs.generation, 0, "{ctx}: server hello has generation 0");
    let compared = Hello {
        generation: expected.generation,
        ..theirs.clone()
    };
    assert_eq!(&compared, expected, "{ctx}");
}

fn hellos(a: &Answer) -> usize {
    a.frames
        .iter()
        .filter(|f| matches!(f, Some(Frame::Hello(_))))
        .count()
}

/// A valid Gloas block envelope with `seq` (unknown or zero types and bad digests derive from it).
fn block(seq: u64) -> Envelope {
    let epoch = fixture::sepolia_schedule()
        .fork_epoch(ForkName::Gloas)
        .expect("Sepolia schedules Gloas");
    Envelope {
        fork_digest: digest_at(ForkName::Gloas, epoch).to_vec(),
        slot: epoch * SLOTS_PER_EPOCH,
        payload_type: PayloadType::SignedBeaconBlock as i32,
        seq,
        ..Default::default()
    }
}

fn typed(seq: u64, payload_type: i32) -> Envelope {
    Envelope {
        payload_type,
        ..block(seq)
    }
}

/// A Gloas slot carrying the last Fulu (BPO) digest.
fn stale_digest(seq: u64) -> Envelope {
    let gloas = fixture::sepolia_schedule()
        .fork_epoch(ForkName::Gloas)
        .expect("Sepolia schedules Gloas");
    Envelope {
        fork_digest: digest_at(ForkName::Fulu, gloas - 1).to_vec(),
        ..block(seq)
    }
}

const UNKNOWN_TYPE: i32 = 999;

impl ContractSuite {
    #[must_use]
    pub fn new(factory: TargetFactory) -> Self {
        Self { factory }
    }

    pub async fn run_in_process(&self, rule: Rule) {
        self.run(rule, &Mode::InProcess).await;
    }

    /// `dir` holds the run's sockets (one per server the rule starts).
    pub async fn run_over_uds(&self, rule: Rule, dir: &Path) {
        self.run(rule, &Mode::over_uds(dir)).await;
    }

    pub async fn run(&self, rule: Rule, mode: &Mode) {
        let base = (self.factory)(fixture::v1_link());
        let surface = surface(base.package);
        check_coverage(&base, &surface);
        let run = Run {
            factory: self.factory,
            mode,
            surface: &surface,
            probe: base.probe.clone(),
            unary: base.unary.clone(),
        };
        match rule {
            Rule::HelloVersionNN1 => run.hello_version_n_n1().await,
            Rule::HelloFloor => run.hello_floor().await,
            Rule::HelloPinMismatch => run.hello_pin_mismatch().await,
            Rule::HelloOnce => run.hello_once().await,
            Rule::SeqMonotonic => run.seq_monotonic().await,
            Rule::EnvelopeTypeRules => run.envelope_type_rules().await,
            Rule::EnvelopeDigestMismatch => run.envelope_digest_mismatch().await,
            Rule::UnaryNoHello => run.unary_no_hello().await,
            Rule::SoPeercred => run.so_peercred().await,
        }
    }
}

/// The target's probes must match the package's real surface.
fn check_coverage(target: &Target, surface: &Surface) {
    let pkg = &surface.package;
    for rpc in surface.streams() {
        assert!(
            rpc.framed,
            "{}: every streamed message must be oneof frame {{ hello = 1; body = 2 }}, and a \
             server-streaming request must carry a Hello",
            rpc.path
        );
    }
    match &target.probe {
        None => assert_eq!(
            surface.streams().count(),
            0,
            "{pkg} has streaming RPCs; the contract target must register a probe"
        ),
        Some(p) => {
            let rpc = surface
                .rpc(p.rpc())
                .unwrap_or_else(|| panic!("probe {} is not an RPC of {pkg}", p.rpc()));
            assert!(rpc.server_streaming, "probe {} must stream", p.rpc());
            assert_eq!(rpc.client_streaming, p.bidi(), "probe {} shape", p.rpc());
            assert_eq!(rpc.request_envelopes, p.request_envelopes(), "{}", p.rpc());
            assert_eq!(
                rpc.response_envelopes,
                p.response_envelopes(),
                "{}",
                p.rpc()
            );
        }
    }
    let unary_envelopes = surface.unary().any(|r| r.request_envelopes);
    match &target.unary {
        None => assert!(
            !unary_envelopes,
            "{pkg} has unary RPCs carrying envelopes; register a unary probe"
        ),
        Some(u) => {
            let rpc = surface
                .rpc(u.rpc())
                .unwrap_or_else(|| panic!("unary probe {} is not an RPC of {pkg}", u.rpc()));
            assert!(!rpc.streaming() && rpc.request_envelopes, "{}", u.rpc());
        }
    }
}

struct Run<'a> {
    factory: TargetFactory,
    mode: &'a Mode,
    surface: &'a Surface,
    probe: Option<Arc<dyn Probe>>,
    unary: Option<Arc<dyn UnaryProbe>>,
}

impl Run<'_> {
    /// The service, built on `link`, answering `steps`.
    async fn ask(&self, link: Link, steps: Vec<Step>) -> (Answer, Target) {
        let probe = self.probe.as_ref().expect("caller checked the probe");
        let target = (self.factory)(link);
        let conn = self.mode.connect(target.server.clone()).await;
        let answer = probe.call(conn.transport.clone(), steps).await;
        (answer, target)
    }

    /// The client guard on `link` against a scripted server answering `steps`.
    async fn guard(&self, link: Link, steps: Vec<Step>) -> Result<GuardReport, ContractError> {
        let probe = self.probe.as_ref().expect("caller checked the probe");
        let conn = self.mode.connect(probe.scripted(steps)).await;
        probe.guarded_call(conn.transport.clone(), link).await
    }

    async fn unary_call(&self, envelopes: Vec<Envelope>) -> (Result<(), tonic::Status>, Target) {
        let unary = self.unary.as_ref().expect("caller checked the unary probe");
        let target = (self.factory)(fixture::v1_link());
        let conn = self.mode.connect(target.server.clone()).await;
        let r = unary.call(conn.transport.clone(), envelopes).await;
        (r, target)
    }

    /// The link of the target the factory builds from `link`, which must be that very link (or a
    /// clone): the rules then judge the configuration the service was built with.
    fn target_link(&self, link: Link) -> Link {
        let target = (self.factory)(link.clone());
        assert!(
            target.link.is_same(&link),
            "{}: the target must be configured with the link it was given (floor {}, \
             versions {}..={}), not its own (floor {}, versions {}..={})",
            self.surface.package,
            link.floor(),
            link.local().min_api_version,
            link.local().max_api_version,
            target.link.floor(),
            target.link.local().min_api_version,
            target.link.local().max_api_version,
        );
        target.link
    }

    fn assert_no_stream(&self) {
        assert_eq!(
            self.surface.streams().count(),
            0,
            "{}: rule has no probe but the package streams",
            self.surface.package
        );
    }

    async fn hello_version_n_n1(&self) {
        // (service range, peer range, negotiated version or a mismatch)
        let cases = [
            ((1, 2), (1, 1), Some(1)),
            ((1, 1), (1, 2), Some(1)),
            ((1, 2), (1, 2), Some(2)),
            ((1, 1), (1, 1), Some(1)),
            ((2, 2), (1, 1), None),
            ((1, 1), (2, 2), None),
        ];
        for ((smin, smax), (cmin, cmax), want) in cases {
            let server = fixture::hello(smin, smax);
            let client = fixture::hello(cmin, cmax);
            let ctx = format!("service {smin}..={smax}, peer {cmin}..={cmax}");
            let link = fixture::link(smin, smax, 1);
            assert_eq!(
                self.target_link(link.clone()).negotiate(&client).ok(),
                want,
                "{ctx}: service-side negotiation"
            );
            if self.probe.is_none() {
                self.assert_no_stream();
                continue;
            }
            let (answer, _) = self.ask(link, vec![Step::Hello(client.clone())]).await;
            match want {
                Some(v) => {
                    let theirs = answer
                        .server_hello()
                        .unwrap_or_else(|| panic!("{ctx}: no server hello: {answer:?}"));
                    assert_server_hello(theirs, &server, &ctx);
                    assert_eq!(negotiate(&client, theirs, 1), Ok(v), "{ctx}: peer side");
                    assert!(answer.reached_handler(), "{ctx}: {answer:?}");
                }
                None => {
                    assert_eq!(
                        code(&answer.error()),
                        Some(ErrorCode::VersionMismatch),
                        "{ctx}"
                    );
                    assert!(
                        answer.server_hello().is_none(),
                        "{ctx}: hello sent on failure"
                    );
                }
            }
            // The peer's guard against a scripted service with the same ranges.
            let report = self
                .guard(fixture::link(cmin, cmax, 1), vec![Step::Hello(server)])
                .await;
            match want {
                Some(v) => assert_eq!(report.map(|r| r.version), Ok(v), "{ctx}: peer guard"),
                None => assert_eq!(
                    report.unwrap_err().code(),
                    ErrorCode::VersionMismatch,
                    "{ctx}: peer guard"
                ),
            }
        }
    }

    async fn hello_floor(&self) {
        let n_minus_1 = fixture::hello(1, 1);
        let n = fixture::hello(1, 2);
        let raised = self.target_link(fixture::link(1, 2, 2));
        assert_eq!(raised.negotiate(&n), Ok(2));
        assert_eq!(
            raised.negotiate(&n_minus_1).unwrap_err().code(),
            ErrorCode::VersionMismatch
        );
        let Some(_) = &self.probe else {
            return self.assert_no_stream();
        };
        let (refused, target) = self
            .ask(fixture::link(1, 2, 2), vec![Step::Hello(n_minus_1.clone())])
            .await;
        assert_eq!(code(&refused.error()), Some(ErrorCode::VersionMismatch));
        assert!(refused.server_hello().is_none());
        assert_eq!(
            (target.violations)(),
            0,
            "a version mismatch is not a violation"
        );
        let (ok, _) = self
            .ask(fixture::link(1, 2, 2), vec![Step::Hello(n.clone())])
            .await;
        assert!(ok.reached_handler(), "{ok:?}");
        assert_eq!(negotiate(&n, ok.server_hello().expect("hello"), 2), Ok(2));
        // The peer enforces its own floor against a service that only speaks N-1.
        let peer = self
            .guard(fixture::link(1, 2, 2), vec![Step::Hello(n_minus_1)])
            .await;
        assert_eq!(peer.unwrap_err().code(), ErrorCode::VersionMismatch);
        assert_eq!(
            self.guard(fixture::link(1, 2, 2), vec![Step::Hello(n)])
                .await
                .map(|r| r.version),
            Ok(2)
        );
    }

    async fn hello_pin_mismatch(&self) {
        type Edit = (&'static str, fn(&mut Hello));
        let edits: Vec<Edit> = vec![
            ("consensus-specs tag", |h| {
                h.spec_pin.as_mut().expect("pin").consensus_specs_tag = "v1.7.0-beta.3".into();
            }),
            ("ssz-specs tag", |h| {
                h.spec_pin.as_mut().expect("pin").ssz_specs_tag = "v0.2.0".into();
            }),
            ("no spec pin", |h| h.spec_pin = None),
            ("future fork epoch", |h| {
                h.fork_schedule.last_mut().expect("entry").epoch += 1;
            }),
            ("BPO digest", |h| h.fork_schedule[1].fork_digest[0] ^= 0xff),
            ("fork schedule entry dropped", |h| {
                h.fork_schedule.pop();
            }),
            ("blob schedule limit", |h| {
                h.blob_schedule[0].max_blobs_per_block += 1
            }),
            ("blob schedule entry dropped", |h| {
                h.blob_schedule.pop();
            }),
        ];
        for (what, edit) in edits {
            let mut theirs = fixture::hello(1, 1);
            edit(&mut theirs);
            assert_eq!(
                self.target_link(fixture::v1_link())
                    .negotiate(&theirs)
                    .unwrap_err()
                    .code(),
                ErrorCode::VersionMismatch,
                "{what}"
            );
            if self.probe.is_none() {
                self.assert_no_stream();
                continue;
            }
            let (answer, _) = self
                .ask(fixture::v1_link(), vec![Step::Hello(theirs.clone())])
                .await;
            assert_eq!(
                code(&answer.error()),
                Some(ErrorCode::VersionMismatch),
                "{what}"
            );
            assert!(answer.server_hello().is_none(), "{what}: no fallback hello");
            let peer = self
                .guard(fixture::v1_link(), vec![Step::Hello(theirs)])
                .await;
            assert_eq!(
                peer.unwrap_err().code(),
                ErrorCode::VersionMismatch,
                "{what}"
            );
        }
    }

    async fn hello_once(&self) {
        let Some(probe) = self.probe.clone() else {
            self.assert_no_stream();
            assert!(
                self.surface.rpcs.iter().all(|r| !r.request_hello),
                "a unary request carries a hello"
            );
            return;
        };
        let hello = || Step::Hello(fixture::hello(1, 1));
        let mut refused = vec![("missing hello", vec![])];
        if probe.bidi() {
            refused.push(("body first", vec![Step::Body(vec![])]));
            refused.push(("empty frame first", vec![Step::Empty]));
            refused.push(("second hello", vec![hello(), hello()]));
            refused.push((
                "hello after a body",
                vec![hello(), Step::Body(vec![]), hello()],
            ));
        }
        for (what, steps) in refused {
            let (answer, target) = self.ask(fixture::v1_link(), steps).await;
            assert_eq!(
                code(&answer.error()),
                Some(ErrorCode::ContractViolation),
                "{what}: {answer:?}"
            );
            assert!(hellos(&answer) <= 1, "{what}: more than one server hello");
            assert!(
                (target.violations)() >= 1,
                "{what}: contract-violation metric"
            );
        }
        // The service opens its own direction with exactly one hello, which carries a fresh
        // non-zero server generation on every stream.
        let (ok, _) = self.ask(fixture::v1_link(), vec![hello()]).await;
        assert!(ok.reached_handler(), "{ok:?}");
        assert_eq!(hellos(&ok), 1, "{ok:?}");
        let first = ok.server_hello().expect("the first server frame is hello");
        assert_server_hello(first, &fixture::hello(1, 1), "hello once");
        let (again, _) = self.ask(fixture::v1_link(), vec![hello()]).await;
        let second = again
            .server_hello()
            .expect("the first server frame is hello");
        assert_ne!(
            first.generation, second.generation,
            "each stream gets its own server generation"
        );
        // The peer refuses a service direction without exactly one leading hello.
        let refused_by_peer = [
            ("no hello", vec![]),
            ("body first", vec![Step::Body(vec![])]),
            ("empty frame", vec![hello(), Step::Empty]),
            ("second hello", vec![hello(), hello()]),
        ];
        for (what, steps) in refused_by_peer {
            let r = self.guard(fixture::v1_link(), steps).await;
            assert_eq!(
                r.unwrap_err().code(),
                ErrorCode::ContractViolation,
                "peer: {what}"
            );
        }
        let fine = self
            .guard(fixture::v1_link(), vec![hello(), Step::Body(vec![])])
            .await;
        assert_eq!(fine.map(|r| r.bodies), Ok(1));
    }

    async fn seq_monotonic(&self) {
        let hello = || Step::Hello(fixture::hello(1, 1));
        let mut covered = false;
        if self.probe.as_ref().is_some_and(|p| p.request_envelopes()) {
            covered = true;
            let (ok, target) = self
                .ask(
                    fixture::v1_link(),
                    vec![
                        hello(),
                        Step::Body(vec![block(1), block(2)]),
                        Step::Body(vec![block(3)]),
                    ],
                )
                .await;
            assert!(ok.reached_handler(), "{ok:?}");
            assert_eq!(target.counts().accepted, 3);
            let refused = [
                ("starts at 0", vec![Step::Body(vec![block(0)])]),
                ("gap from the start", vec![Step::Body(vec![block(2)])]),
                (
                    "repeat in a body",
                    vec![Step::Body(vec![block(1), block(1)])],
                ),
                (
                    "decrease across bodies",
                    vec![
                        Step::Body(vec![block(1), block(2)]),
                        Step::Body(vec![block(1)]),
                    ],
                ),
                (
                    "gap across bodies",
                    vec![Step::Body(vec![block(1)]), Step::Body(vec![block(3)])],
                ),
            ];
            for (what, bodies) in refused {
                let mut steps = vec![hello()];
                steps.extend(bodies);
                let (answer, target) = self.ask(fixture::v1_link(), steps).await;
                assert_eq!(
                    code(&answer.error()),
                    Some(ErrorCode::ContractViolation),
                    "{what}: {answer:?}"
                );
                assert_eq!(target.counts().contract_violations, 1, "{what}");
            }
        }
        if self.probe.as_ref().is_some_and(|p| p.response_envelopes()) {
            covered = true;
            let ok = self
                .guard(
                    fixture::v1_link(),
                    vec![
                        hello(),
                        Step::Body(vec![block(1)]),
                        Step::Body(vec![block(2)]),
                    ],
                )
                .await;
            assert_eq!(ok.map(|r| r.bodies), Ok(2));
            for (what, bodies) in [
                ("repeat", vec![block(1), block(1)]),
                ("gap", vec![block(2)]),
                ("zero", vec![block(0)]),
            ] {
                let mut steps = vec![hello()];
                steps.extend(bodies.into_iter().map(|e| Step::Body(vec![e])));
                let r = self.guard(fixture::v1_link(), steps).await;
                assert_eq!(
                    r.unwrap_err().code(),
                    ErrorCode::ContractViolation,
                    "peer: {what}"
                );
            }
        }
        if self.unary.is_some() {
            covered = true;
            let (ok, _) = self.unary_call(vec![block(0), block(0)]).await;
            assert!(unimplemented_or_ok(&ok), "{ok:?}");
            let (refused, target) = self.unary_call(vec![block(1)]).await;
            assert_eq!(status_code(&refused), Some(ErrorCode::ContractViolation));
            assert_eq!(target.counts().contract_violations, 1);
        }
        if !covered {
            assert!(
                !self.surface.carries_envelopes(),
                "{} carries envelopes but no probe covers them",
                self.surface.package
            );
        }
    }

    async fn envelope_type_rules(&self) {
        let link = fixture::v1_link();
        assert_eq!(
            link.check_envelope(&typed(1, 0)).unwrap_err(),
            EnvelopeError::UnspecifiedType
        );
        assert!(link
            .check_envelope(&typed(1, UNKNOWN_TYPE))
            .unwrap_err()
            .is_ignore());
        let hello = || Step::Hello(fixture::hello(1, 1));
        let mut covered = false;
        if self.probe.as_ref().is_some_and(|p| p.request_envelopes()) {
            covered = true;
            let (zero, target) = self
                .ask(
                    fixture::v1_link(),
                    vec![hello(), Step::Body(vec![typed(1, 0)])],
                )
                .await;
            assert_eq!(
                code(&zero.error()),
                Some(ErrorCode::ContractViolation),
                "{zero:?}"
            );
            assert_eq!(target.counts().contract_violations, 1);
            let (unknown, target) = self
                .ask(
                    fixture::v1_link(),
                    vec![hello(), Step::Body(vec![typed(1, UNKNOWN_TYPE), block(2)])],
                )
                .await;
            assert!(
                unknown.reached_handler(),
                "unknown type must not fail: {unknown:?}"
            );
            let c = target.counts();
            assert_eq!((c.ignored, c.accepted, c.contract_violations), (1, 1, 0));
        }
        if self.probe.as_ref().is_some_and(|p| p.response_envelopes()) {
            covered = true;
            let zero = self
                .guard(
                    fixture::v1_link(),
                    vec![hello(), Step::Body(vec![typed(1, 0)])],
                )
                .await;
            assert_eq!(zero.unwrap_err().code(), ErrorCode::ContractViolation);
            let unknown = self
                .guard(
                    fixture::v1_link(),
                    vec![
                        hello(),
                        Step::Body(vec![typed(1, UNKNOWN_TYPE)]),
                        Step::Body(vec![block(2)]),
                    ],
                )
                .await;
            assert_eq!(unknown.map(|r| (r.bodies, r.dropped)), Ok((2, 1)));
        }
        if self.unary.is_some() {
            covered = true;
            let (zero, _) = self.unary_call(vec![typed(0, 0)]).await;
            assert_eq!(status_code(&zero), Some(ErrorCode::ContractViolation));
            let (unknown, target) = self.unary_call(vec![typed(0, UNKNOWN_TYPE)]).await;
            assert!(unimplemented_or_ok(&unknown), "{unknown:?}");
            assert_eq!(target.counts().ignored, 1);
        }
        if !covered {
            assert!(
                !self.surface.carries_envelopes(),
                "{}",
                self.surface.package
            );
        }
    }

    async fn envelope_digest_mismatch(&self) {
        let link = fixture::v1_link();
        let gloas = fixture::sepolia_schedule()
            .fork_epoch(ForkName::Gloas)
            .expect("Gloas");
        let last_fulu = Envelope {
            slot: gloas * SLOTS_PER_EPOCH - 1,
            ..block(1)
        };
        assert!(matches!(
            link.check_envelope(&stale_digest(1)),
            Err(EnvelopeError::DigestMismatch { .. })
        ));
        assert!(matches!(
            link.check_envelope(&last_fulu),
            Err(EnvelopeError::DigestMismatch { .. })
        ));
        assert!(link.check_envelope(&block(1)).is_ok());
        let hello = || Step::Hello(fixture::hello(1, 1));
        let mut covered = false;
        if self.probe.as_ref().is_some_and(|p| p.request_envelopes()) {
            covered = true;
            let (answer, target) = self
                .ask(
                    fixture::v1_link(),
                    vec![hello(), Step::Body(vec![stale_digest(1), block(2)])],
                )
                .await;
            assert!(
                answer.reached_handler(),
                "a mismatch drops, not fails: {answer:?}"
            );
            let c = target.counts();
            assert_eq!((c.digest_mismatches, c.accepted), (1, 1));
        }
        if self.probe.as_ref().is_some_and(|p| p.response_envelopes()) {
            covered = true;
            let r = self
                .guard(
                    fixture::v1_link(),
                    vec![
                        hello(),
                        Step::Body(vec![stale_digest(1)]),
                        Step::Body(vec![block(2)]),
                    ],
                )
                .await;
            assert_eq!(r.map(|r| (r.bodies, r.dropped)), Ok((2, 1)));
        }
        if self.unary.is_some() {
            covered = true;
            let (r, target) = self.unary_call(vec![stale_digest(0)]).await;
            assert!(unimplemented_or_ok(&r), "{r:?}");
            assert_eq!(target.counts().digest_mismatches, 1);
        }
        if !covered {
            assert!(
                !self.surface.carries_envelopes(),
                "{}",
                self.surface.package
            );
        }
    }

    async fn unary_no_hello(&self) {
        let unary: Vec<String> = self
            .surface
            .unary()
            .map(|r| {
                assert!(
                    !r.request_hello,
                    "{}: unary request carries a hello",
                    r.path
                );
                r.path.clone()
            })
            .collect();
        if unary.is_empty() {
            return;
        }
        let target = (self.factory)(fixture::v1_link());
        let conn = self.mode.connect(target.server.clone()).await;
        for rpc in unary {
            let r = call_unary_empty(conn.transport.clone(), &rpc).await;
            if let Err(status) = &r {
                // tonic answers an unrouted call itself with a bare UNIMPLEMENTED (or NOT_FOUND):
                // only a stub's own message, or any other status, shows a handler ran.
                let by_stub = status
                    .message()
                    .ends_with(crate::stub::NOT_IMPLEMENTED_SUFFIX);
                assert!(
                    by_stub
                        || !matches!(
                            status.code(),
                            tonic::Code::Unimplemented | tonic::Code::NotFound
                        ),
                    "{rpc}: no handler answered ({status:?})"
                );
                let e = ContractError::from_status(status);
                assert_ne!(e.code(), ErrorCode::VersionMismatch, "{rpc}: {e}");
                assert!(
                    !(e.code() == ErrorCode::ContractViolation && e.detail().contains("hello")),
                    "{rpc} wants a hello: {e}"
                );
            }
        }
        assert_eq!(
            (target.violations)(),
            0,
            "unary calls without hello are not violations"
        );
    }

    /// Calls every RPC through the target behind `acl`; returns which were let through, and
    /// checks that exactly those reached the target.
    async fn calls_through(&self, acl: MethodAcl, credentials: bool) -> Vec<bool> {
        let target = (self.factory)(fixture::v1_link());
        let conn = self
            .mode
            .connect_behind_acl(target.server.clone(), Arc::new(acl), credentials)
            .await;
        let mut passed = Vec::new();
        for rpc in &self.surface.rpcs {
            let r = call_unary_empty(conn.connection.transport.clone(), &rpc.path).await;
            passed.push(!is_denied(&r));
        }
        let allowed = passed.iter().filter(|p| **p).count() as u64;
        assert_eq!(
            conn.reached(),
            allowed,
            "denied calls must not reach the service"
        );
        passed
    }

    async fn so_peercred(&self) {
        let package = &self.surface.package;
        let service = acl::service_of(package).expect("a service package");
        let (me, other) = (peercred::effective_uid(), another_uid());
        let paths: Vec<String> = self.surface.rpcs.iter().map(|r| r.path.clone()).collect();
        assert!(!paths.is_empty(), "{package} has no RPC");
        let grant =
            |uid: u32| -> Vec<(String, u32)> { paths.iter().map(|p| (p.clone(), uid)).collect() };
        let all = vec![true; paths.len()];
        let none = vec![false; paths.len()];

        // Every method ours: every call passes the ACL.
        let ours = acl_of(&service, &grant(me)).expect("ACL loads");
        assert_eq!(
            self.calls_through(ours.clone(), true).await,
            all,
            "{service}: allowed"
        );
        // Our UID is on the socket but not listed for the method.
        match acl::sole_caller(&service) {
            Some(only) => {
                // cl-chain is someone else: we are refused on every method.
                let theirs = acl_of(&service, &grant(other)).expect("ACL loads");
                assert_eq!(
                    self.calls_through(theirs, true).await,
                    none,
                    "{service}: not {only}"
                );
                // A second caller, or any caller but cl-chain, does not even load.
                for callers in [
                    vec![only.to_owned(), "cl-api".into()],
                    vec!["cl-api".into()],
                ] {
                    let tables = AclTables {
                        callers: [(only.to_owned(), me), ("cl-api".to_owned(), other)].into(),
                        methods: [(paths[0].clone(), callers.clone())].into(),
                    };
                    assert!(
                        matches!(
                            MethodAcl::from_tables(&service, &tables),
                            Err(AclError::SoleCaller { .. })
                        ),
                        "{service} allows {callers:?}"
                    );
                }
            }
            None => {
                // The first method is fenced to another UID; the rest stay ours.
                let mut grants = grant(me);
                grants[0].1 = other;
                let fenced = acl_of(&service, &grants).expect("ACL loads");
                let mut want = all.clone();
                want[0] = false;
                assert_eq!(
                    self.calls_through(fenced, true).await,
                    want,
                    "{service}: fenced"
                );
            }
        }
        // A method the ACL does not list is denied (the ACL names only a method nobody serves).
        let unlisted =
            acl_of(&service, &[(format!("/{package}.Unlisted/Probe"), me)]).expect("ACL loads");
        assert_eq!(
            self.calls_through(unlisted, true).await,
            none,
            "{service}: unlisted"
        );
        // No peer credentials (only possible in process; a Unix socket always has them).
        if matches!(self.mode, Mode::InProcess) {
            assert_eq!(
                self.calls_through(ours.clone(), false).await,
                none,
                "no credentials"
            );
        }

        // The peer side: a server running as another user is refused before a byte is sent.
        let refused = peercred::expect_uid(Ok(super::own_cred()), other);
        assert!(
            matches!(refused, Err(PeerCredError::WrongUid { .. })),
            "{refused:?}"
        );
        let gone = peercred::expect_uid(Err(std::io::ErrorKind::NotConnected.into()), me);
        assert!(
            matches!(gone, Err(PeerCredError::Unavailable(_))),
            "{gone:?}"
        );
        if let Mode::Uds(_) = self.mode {
            let target = (self.factory)(fixture::v1_link());
            let conn = self
                .mode
                .connect_behind_acl(target.server.clone(), Arc::new(ours), true)
                .await;
            let socket = conn.socket.clone().expect("a socket");
            let err = tonic::transport::Endpoint::from_static("http://localhost")
                .connect_with_connector(PeerCheckedConnector::new(&socket, other))
                .await
                .expect_err("a server with another UID is refused");
            assert!(
                matches!(
                    uds::peer_refusal(&err),
                    Some(PeerCredError::WrongUid { .. })
                ),
                "{err:?}"
            );
            assert_eq!(conn.reached(), 0, "nothing reached the refused server");
            let channel = uds::connect_path(&socket, me)
                .await
                .expect("our own UID is accepted");
            let transport =
                tower::util::BoxCloneSyncService::new(tower::ServiceExt::map_err(channel, |e| {
                    super::TransportError(e.into())
                }));
            let r = call_unary_empty(transport, &paths[0]).await;
            assert!(!is_denied(&r), "{r:?}");
            assert_eq!(conn.reached(), 1);
        }
    }
}

/// A UID that is not ours (nor the invalid `u32::MAX`).
fn another_uid() -> u32 {
    match peercred::effective_uid().checked_add(1) {
        Some(u) if u != u32::MAX => u,
        _ => 0,
    }
}

/// An ACL of `service` giving each `(method, uid)` to a caller with that UID.
fn acl_of(service: &str, grants: &[(String, u32)]) -> Result<MethodAcl, AclError> {
    let only = acl::sole_caller(service);
    let mut tables = AclTables::default();
    for (method, uid) in grants {
        // A sole-caller service can only name its one caller; elsewhere any name will do.
        let name = only.map_or_else(|| format!("uid-{uid}"), str::to_owned);
        tables.callers.insert(name.clone(), *uid);
        tables.methods.insert(method.clone(), vec![name]);
    }
    MethodAcl::from_tables(service, &tables)
}

fn is_denied(r: &Result<(), tonic::Status>) -> bool {
    match r {
        Err(s) if s.code() == tonic::Code::PermissionDenied => {
            assert_eq!(
                ContractError::from_status(s).code(),
                ErrorCode::ContractViolation,
                "{s:?}"
            );
            true
        }
        _ => false,
    }
}

fn status_code(r: &Result<(), tonic::Status>) -> Option<ErrorCode> {
    match r {
        Err(s) if s.code() != tonic::Code::Unimplemented => {
            Some(ContractError::from_status(s).code())
        }
        _ => None,
    }
}

fn unimplemented_or_ok(r: &Result<(), tonic::Status>) -> bool {
    status_code(r).is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names_are_unique_and_listed_for_ci() {
        let names: Vec<&str> = Rule::ALL.iter().map(|r| r.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
        let listed = include_str!("../../contract-rules.txt");
        let listed: Vec<&str> = listed
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(
            listed, names,
            "crates/ipc/contract-rules.txt must list Rule::ALL in order"
        );
    }

    use crate::testkit::block_on;
    use tonic::service::Routes;

    /// A unary-only package whose routes serve nothing: tonic answers every call itself.
    fn empty_api(link: Link) -> Target {
        Target::new("ethswarm.api.v1", Server::new(Routes::default()), link)
    }

    /// A target that drops the link it is given and uses a v1-only, floor-1 one instead.
    fn ignores_its_link(_: Link) -> Target {
        let own = fixture::v1_link();
        Target::new("ethswarm.engine.v1", Server::new(Routes::default()), own)
    }

    #[test]
    #[should_panic(expected = "no handler answered")]
    fn unary_no_hello_fails_when_no_handler_is_served_in_process() {
        block_on(ContractSuite::new(empty_api).run_in_process(Rule::UnaryNoHello));
    }

    #[test]
    #[should_panic(expected = "no handler answered")]
    fn unary_no_hello_fails_when_no_handler_is_served_over_uds() {
        let dir = crate::testkit::tempdir();
        block_on(ContractSuite::new(empty_api).run_over_uds(Rule::UnaryNoHello, dir.path()));
    }

    #[test]
    fn hello_rules_check_the_link_the_target_was_given() {
        for rule in [
            Rule::HelloVersionNN1,
            Rule::HelloFloor,
            Rule::HelloPinMismatch,
        ] {
            let r = std::panic::catch_unwind(|| {
                block_on(ContractSuite::new(ignores_its_link).run_in_process(rule));
            });
            let msg = r.expect_err("a target ignoring its link must fail");
            let msg = msg
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| msg.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_default();
            assert!(msg.contains("the link it was given"), "{rule:?}: {msg}");
        }
    }

    #[test]
    fn fixture_envelopes_pass_the_fixture_link() {
        let link = fixture::v1_link();
        assert!(link.check_envelope(&block(1)).is_ok());
        assert!(link.check_envelope(&stale_digest(1)).is_err());
    }
}
