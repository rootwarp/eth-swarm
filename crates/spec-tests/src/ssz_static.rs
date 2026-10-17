//! consensus-spec-tests `tests/<preset>/<fork>/ssz_static/<Type>/<suite>/<case>/`.
//!
//! Each case holds `serialized.ssz_snappy` (snappy block format) and `roots.yaml`.
//! The check is decode, re-encode to identical bytes, and `hash_tree_root`.

use crate::check::{parse_hex, round_trip, Expect};
use crate::plan::CaseKey;
use crate::ssz_generic::{file_name, sorted_dir};
use consensus_types::{fulu, gloas, EthSpec, Mainnet, Minimal};
use std::path::{Path, PathBuf};

/// A discovered ssz_static case.
#[derive(Debug)]
pub struct StaticCase {
    /// Skip-list key; `case` is `<suite>/<case>`.
    pub key: CaseKey,
    /// The case directory.
    pub dir: PathBuf,
}

/// Lists every case under `<root>/tests/<preset>/<fork>/ssz_static`.
pub fn discover(root: &Path, preset: &str, fork: &str) -> std::io::Result<Vec<StaticCase>> {
    let base = root
        .join("tests")
        .join(preset)
        .join(fork)
        .join("ssz_static");
    let mut out = Vec::new();
    for handler in sorted_dir(&base)? {
        for suite in sorted_dir(&handler)? {
            for case in sorted_dir(&suite)? {
                out.push(StaticCase {
                    key: CaseKey {
                        source: "consensus-specs".into(),
                        fork: fork.into(),
                        preset: preset.into(),
                        runner: "ssz_static".into(),
                        handler: file_name(&handler),
                        case: format!("{}/{}", file_name(&suite), file_name(&case)),
                    },
                    dir: case,
                });
            }
        }
    }
    Ok(out)
}

/// Extracts `root: '0x..'` from `roots.yaml` without a YAML dependency.
fn parse_root(yaml: &str) -> Result<[u8; 32], String> {
    let line = yaml
        .lines()
        .find_map(|l| l.trim().strip_prefix("root:"))
        .ok_or("roots.yaml has no `root:`")?;
    let hex = line.trim().trim_matches(|c| c == '\'' || c == '"');
    parse_hex(hex)?
        .try_into()
        .map_err(|_| format!("root {hex:?} is not 32 bytes"))
}

/// Whether a handler has a Rust type for this fork and preset.
pub fn supported(fork: &str, preset: &str, handler: &str) -> bool {
    dispatch(fork, preset, handler, &[], &Expect::Invalid).is_some()
}

/// Runs one case. `Err` describes a failure.
pub fn run(case: &StaticCase) -> Result<(), String> {
    let compressed = std::fs::read(case.dir.join("serialized.ssz_snappy"))
        .map_err(|e| format!("serialized.ssz_snappy: {e}"))?;
    let bytes = snap::raw::Decoder::new()
        .decompress_vec(&compressed)
        .map_err(|e| format!("snappy: {e}"))?;
    let yaml = std::fs::read_to_string(case.dir.join("roots.yaml"))
        .map_err(|e| format!("roots.yaml: {e}"))?;
    let expect = Expect::Valid {
        root: parse_root(&yaml)?,
    };
    let k = &case.key;
    dispatch(&k.fork, &k.preset, &k.handler, &bytes, &expect)
        .ok_or_else(|| format!("no Rust type for {}/{}", k.fork, k.handler))?
}

fn dispatch(
    fork: &str,
    preset: &str,
    handler: &str,
    b: &[u8],
    e: &Expect,
) -> Option<Result<(), String>> {
    match (fork, preset) {
        ("fulu", "minimal") => fulu_table::<Minimal>(handler, b, e),
        ("fulu", "mainnet") => fulu_table::<Mainnet>(handler, b, e),
        ("gloas", "minimal") => gloas_table::<Minimal>(handler, b, e),
        ("gloas", "mainnet") => gloas_table::<Mainnet>(handler, b, e),
        _ => None,
    }
}

/// Maps handler names to `consensus-types` containers of one fork module. `plain` types take
/// no preset; `generic` ones are instantiated with `E`.
macro_rules! fork_table {
    ($fn:ident, $m:ident; plain: [$($p:ident),* $(,)?]; generic: [$($g:ident),* $(,)?]) => {
        fn $fn<E: EthSpec>(handler: &str, b: &[u8], e: &Expect) -> Option<Result<(), String>> {
            Some(match handler {
                $(stringify!($p) => round_trip::<$m::$p>(b, e),)*
                $(stringify!($g) => round_trip::<$m::$g<E>>(b, e),)*
                _ => return None,
            })
        }
    };
}

/// Containers whose shape is the same in Fulu and Gloas, as `fork_table!` arguments.
macro_rules! with_common {
    ($fn:ident, $m:ident; plain: [$($p:ident),* $(,)?]; generic: [$($g:ident),* $(,)?]) => {
        fork_table!($fn, $m;
            plain: [
                AttestationData, BLSToExecutionChange, BeaconBlockHeader, Checkpoint,
                ConsolidationRequest, Deposit, DepositData, DepositMessage, DepositRequest,
                Eth1Block, Eth1Data, Fork, ForkData, HistoricalSummary, PendingConsolidation,
                PendingDeposit, PendingPartialWithdrawal, PowBlock, ProposerSlashing,
                SignedBLSToExecutionChange, SignedBeaconBlockHeader, SignedVoluntaryExit,
                SigningData, SingleAttestation, SyncAggregatorSelectionData, SyncCommitteeMessage,
                Validator, VoluntaryExit, Withdrawal, WithdrawalRequest, $($p),*
            ];
            generic: [
                ContributionAndProof, SignedContributionAndProof, SyncAggregate, SyncCommittee,
                SyncCommitteeContribution, AggregateAndProof, Attestation, AttesterSlashing,
                BeaconBlock, BeaconBlockBody, BeaconState, ExecutionPayload, ExecutionRequests,
                IndexedAttestation, NewPayloadRequest, SignedAggregateAndProof, SignedBeaconBlock,
                $($g),*
            ]);
    };
}

with_common!(fulu_table, fulu; plain: []; generic: [ExecutionPayloadHeader]);

with_common!(gloas_table, gloas;
plain: [
    Builder, BuilderDepositRequest, BuilderExitRequest, BuilderPendingPayment,
    BuilderPendingWithdrawal, PayloadAttestationData, PayloadAttestationMessage,
    ProposerPreferences, SignedProposerPreferences,
];
generic: [
    ExecutionPayloadBid, ExecutionPayloadEnvelope, IndexedPayloadAttestation,
    PayloadAttestation, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_root() {
        let y = "root: '0x240f7e97b8d65d116aef12c65909d14e036fbc6b7dbf90249ac5ab40ba9797c5'\n";
        assert_eq!(parse_root(y).unwrap()[0], 0x24);
        assert!(parse_root("nope: 1").is_err());
    }

    #[test]
    fn known_and_unknown_handlers() {
        for preset in ["minimal", "mainnet"] {
            for fork in ["fulu", "gloas"] {
                assert!(supported(fork, preset, "BeaconState"));
                assert!(supported(fork, preset, "Checkpoint"));
                assert!(!supported(fork, preset, "DataColumnSidecar"));
                assert!(!supported(fork, preset, "LightClientHeader"));
            }
            assert!(supported("gloas", preset, "ExecutionPayloadBid"));
            assert!(!supported("fulu", preset, "ExecutionPayloadBid"));
            assert!(supported("fulu", preset, "ExecutionPayloadHeader"));
            assert!(!supported("gloas", preset, "ExecutionPayloadHeader"));
        }
        assert!(!supported("gloas", "gnosis", "BeaconState"));
        assert!(!supported("electra", "minimal", "BeaconState"));
    }
}
