//! consensus-spec-tests `tests/<preset>/<fork>/ssz_static/<Type>/<suite>/<case>/`.
//!
//! Each case holds `serialized.ssz_snappy` (snappy block format) and `roots.yaml`.
//! The check is decode, re-encode to identical bytes, and `hash_tree_root`.

use crate::check::{parse_hex, round_trip, Expect};
use crate::gloas::types as g;
use crate::plan::CaseKey;
use crate::ssz_generic::{file_name, sorted_dir};
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

/// Whether a handler has a Rust type for this preset.
pub fn supported(preset: &str, handler: &str) -> bool {
    dispatch(preset, handler, &[], &Expect::Invalid).is_some()
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
    dispatch(&case.key.preset, &case.key.handler, &bytes, &expect)
        .ok_or_else(|| format!("no Rust type for {}", case.key.handler))?
}

macro_rules! table {
    ($p:expr, $h:expr, $b:expr, $e:expr; $($name:ident),* $(,)?) => {
        match ($p, $h) {
            $(("minimal", stringify!($name)) => Some(round_trip::<g::minimal::$name>($b, $e)),)*
            $(("mainnet", stringify!($name)) => Some(round_trip::<g::mainnet::$name>($b, $e)),)*
            _ => None,
        }
    };
}

fn dispatch(preset: &str, handler: &str, b: &[u8], e: &Expect) -> Option<Result<(), String>> {
    table!(preset, handler, b, e;
        AggregateAndProof, Attestation, AttestationData, AttesterSlashing, BLSToExecutionChange,
        BeaconBlock, BeaconBlockBody, BeaconBlockHeader, BeaconState, Builder, BuilderDepositRequest,
        BuilderExitRequest, BuilderPendingPayment, BuilderPendingWithdrawal, Checkpoint,
        ConsolidationRequest, ContributionAndProof, Deposit, DepositData, DepositMessage,
        DepositRequest, Eth1Block, Eth1Data, ExecutionPayload, ExecutionPayloadBid,
        ExecutionPayloadEnvelope, ExecutionRequests, Fork, ForkData, HistoricalSummary,
        IndexedAttestation, IndexedPayloadAttestation, NewPayloadRequest, PayloadAttestation,
        PayloadAttestationData, PayloadAttestationMessage, PendingConsolidation, PendingDeposit,
        PendingPartialWithdrawal, PowBlock, ProposerPreferences, ProposerSlashing,
        SignedAggregateAndProof, SignedBLSToExecutionChange, SignedBeaconBlock,
        SignedBeaconBlockHeader, SignedContributionAndProof, SignedExecutionPayloadBid,
        SignedExecutionPayloadEnvelope, SignedProposerPreferences, SignedVoluntaryExit,
        SigningData, SingleAttestation, SyncAggregate, SyncAggregatorSelectionData, SyncCommittee,
        SyncCommitteeContribution, SyncCommitteeMessage, Validator, VoluntaryExit, Withdrawal,
        WithdrawalRequest,
    )
}

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
            assert!(supported(preset, "BeaconState"));
            assert!(supported(preset, "ExecutionPayloadBid"));
            assert!(!supported(preset, "DataColumnSidecar"));
        }
        assert!(!supported("gnosis", "BeaconState"));
    }
}
