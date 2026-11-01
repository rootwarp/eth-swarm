//! The generated systemd units (`cl_node::units`) against golden files and against the
//! architecture's tables, kept here as independent copies: ARCH §9 (MemoryMax), ARCH V-9 (who
//! calls whom), ADR-009 (credentials) and Vera's M4 hardening list.
//!
//! Every security property is a checker that returns its findings. Each test runs the checker on
//! the generated units (no finding) and on copies with the line removed or weakened (a finding),
//! so a test cannot pass by checking nothing.
//!
//! `UPDATE_GOLDEN=1 cargo test -p cl-node --test units units_golden` rewrites the golden files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use cl_node::units::{generate, Config, LOOPBACK_ADDRESS_FAMILIES};

/// The services in start order (issue #205): the oracle for names and order.
const SERVICES: [&str; 8] = [
    "verify", "engine", "chain", "store", "discv5", "p2p", "sync", "api",
];

/// ARCH §9 MemoryMax, MiB.
const MEMORY_MAX_MIB: [(&str, u64); 8] = [
    ("chain", 3072),
    ("verify", 512),
    ("engine", 256),
    ("store", 512),
    ("p2p", 768),
    ("discv5", 128),
    ("sync", 1024),
    ("api", 1024),
];

/// ARCH V-9: each service and the services that call it. cl-api's caller is the operator's
/// cl-node, which is not a unit.
const CALLERS: [(&str, &[&str]); 8] = [
    ("chain", &["p2p", "sync", "api", "store"]),
    ("verify", &["chain"]),
    ("engine", &["chain"]),
    ("store", &["api", "sync", "p2p"]),
    ("p2p", &["chain", "sync", "api"]),
    ("discv5", &["p2p", "api"]),
    ("sync", &["api"]),
    ("api", &[]),
];

/// Vera's M4 hardening list, plus `ProcSubset=pid` and `UMask=0077` (the ops/probe block):
/// every unit, exactly these values, `SystemCallFilter` twice in this order.
const HARDENING: [(&str, &str); 25] = [
    ("NoNewPrivileges", "yes"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "yes"),
    ("PrivateTmp", "yes"),
    ("PrivateDevices", "yes"),
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    ("SystemCallFilter", "@system-service"),
    ("SystemCallFilter", "~@privileged"),
    ("SystemCallArchitectures", "native"),
    ("RestrictNamespaces", "yes"),
    ("RestrictRealtime", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("LockPersonality", "yes"),
    ("MemoryDenyWriteExecute", "yes"),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectKernelLogs", "yes"),
    ("ProtectControlGroups", "yes"),
    ("ProtectClock", "yes"),
    ("ProtectHostname", "yes"),
    ("ProtectProc", "invisible"),
    ("ProcSubset", "pid"),
    ("UMask", "0077"),
    ("NotifyAccess", "main"),
];

/// RestrictAddressFamilies= per service: AF_UNIX for the sockets, IP for the [`NETWORK`]
/// services (AF_NETLINK too for cl-p2p's interface watch). The others are loopback only: the
/// ruling's [`LOOPBACK_ADDRESS_FAMILIES`], for the /metrics svc-runtime binds on 127.0.0.1.
const ADDRESS_FAMILIES: [(&str, &str); 8] = [
    ("verify", LOOPBACK_ADDRESS_FAMILIES),
    ("engine", "AF_UNIX AF_INET AF_INET6"),
    ("chain", LOOPBACK_ADDRESS_FAMILIES),
    ("store", LOOPBACK_ADDRESS_FAMILIES),
    ("discv5", "AF_UNIX AF_INET AF_INET6"),
    ("p2p", "AF_UNIX AF_INET AF_INET6 AF_NETLINK"),
    ("sync", LOOPBACK_ADDRESS_FAMILIES),
    ("api", "AF_UNIX AF_INET AF_INET6"),
];

/// What [`LOOPBACK_ADDRESS_FAMILIES`] may be: AF_INET is required (/metrics on 127.0.0.1),
/// AF_INET6 is a ruling that may still change. Today's ruling is the first.
const LOOPBACK_RULINGS: [&str; 2] = ["AF_UNIX AF_INET", "AF_UNIX AF_INET AF_INET6"];

/// The services that talk to the network (the EL, discovery, peers, the REST API). Every other
/// unit is loopback only: exactly `IPAddressAllow=localhost` and `IPAddressDeny=any`.
const NETWORK: [&str; 4] = ["engine", "discv5", "p2p", "api"];

/// The loopback pair of a unit that is not in [`NETWORK`].
const LOOPBACK: [&str; 2] = ["IPAddressAllow=localhost", "IPAddressDeny=any"];

/// ADR-009: the only credentials, by service.
const CREDENTIALS: [(&str, &str); 3] = [
    ("engine", "jwt:/etc/ethswarm/credentials/jwt"),
    ("p2p", "nodekey:/etc/ethswarm/credentials/nodekey"),
    ("discv5", "nodekey:/etc/ethswarm/credentials/nodekey"),
];

/// ARCH: the services that keep state on disk.
const STATEFUL: [&str; 5] = ["chain", "verify", "p2p", "discv5", "sync"];

const TARGET: &str = "ethswarm.target";

fn unit_name(svc: &str) -> String {
    format!("ethswarm-{svc}.service")
}

type Units = BTreeMap<String, String>;

fn units(config: &Config) -> Units {
    generate(config)
        .into_iter()
        .map(|u| (u.name, u.text))
        .collect()
}

fn default_units() -> Units {
    units(&Config::default())
}

fn supernode_units() -> Units {
    units(&Config::new("mainnet", true, Path::new("/usr/local/bin")).unwrap())
}

/// `(section, key, value)` of every assignment, in order; comments and blank lines skipped.
fn entries(text: &str) -> Vec<(String, String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_owned();
            continue;
        }
        let (k, v) = line.split_once('=').expect("key=value");
        out.push((section.clone(), k.trim().to_owned(), v.trim().to_owned()));
    }
    out
}

/// Every value of `key` in `section`, in order.
fn values(text: &str, section: &str, key: &str) -> Vec<String> {
    entries(text)
        .into_iter()
        .filter(|(s, k, _)| s == section && k == key)
        .map(|(_, _, v)| v)
        .collect()
}

/// The single value of `key`, or a finding.
fn one(text: &str, section: &str, key: &str) -> Result<String, String> {
    match values(text, section, key).as_slice() {
        [v] => Ok(v.clone()),
        vs => Err(format!("[{section}] {key}= appears {} times", vs.len())),
    }
}

fn service_unit<'a>(units: &'a Units, svc: &str) -> &'a str {
    units
        .get(&unit_name(svc))
        .unwrap_or_else(|| panic!("no unit for {svc}"))
}

/// `text` without its first line that is exactly `line`.
fn without(text: &str, line: &str) -> String {
    let mut done = false;
    let mut out = String::new();
    for l in text.lines() {
        if !done && l == line {
            done = true;
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    assert!(done, "mutation: no line {line:?} in\n{text}");
    out
}

/// `text` with `extra` appended at the end of `[section]`.
fn with(text: &str, section: &str, extra: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    let mut done = false;
    for l in text.lines() {
        if l.starts_with('[') {
            if inside && !done {
                out.push_str(extra);
                out.push('\n');
                done = true;
            }
            inside = l == format!("[{section}]");
        }
        out.push_str(l);
        out.push('\n');
    }
    if inside && !done {
        out.push_str(extra);
        out.push('\n');
        done = true;
    }
    assert!(done, "mutation: no [{section}] in\n{text}");
    out
}

/// `units` with the unit of `svc` replaced by `f(text)`.
fn mutate(units: &Units, svc: &str, f: impl FnOnce(&str) -> String) -> Units {
    let mut out = units.clone();
    let name = unit_name(svc);
    let text = f(&out[&name]);
    out.insert(name, text);
    out
}

#[track_caller]
fn assert_clean(findings: Vec<String>) {
    assert!(findings.is_empty(), "findings:\n{}", findings.join("\n"));
}

#[track_caller]
fn assert_caught(what: &str, findings: Vec<String>) {
    assert!(
        !findings.is_empty(),
        "the check did not catch the mutation: {what}"
    );
}

// --- checkers --------------------------------------------------------------------------------

fn mib(value: &str) -> u64 {
    if let Some(g) = value.strip_suffix('G') {
        g.parse::<u64>().unwrap() * 1024
    } else if let Some(m) = value.strip_suffix('M') {
        m.parse().unwrap()
    } else {
        panic!("MemoryMax={value}: not <n>G or <n>M")
    }
}

fn memory_findings(units: &Units, supernode: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut total = 0;
    for (svc, arch) in MEMORY_MAX_MIB {
        let text = service_unit(units, svc);
        let want = if supernode && svc == "p2p" {
            1536
        } else {
            arch
        };
        match one(text, "Service", "MemoryMax") {
            Ok(v) if mib(&v) == want => total += want,
            Ok(v) => out.push(format!("{svc}: MemoryMax={v}, ARCH §9 says {want}M")),
            Err(e) => out.push(format!("{svc}: {e}")),
        }
        let high = values(text, "Service", "MemoryHigh");
        let swap = values(text, "Service", "MemorySwapMax");
        let (want_high, want_swap): (&[&str], &[&str]) = match svc {
            "chain" => (&["2G"], &["0"]),
            "p2p" if supernode => (&["1G"], &[]),
            _ => (&[], &[]),
        };
        if high != want_high {
            out.push(format!("{svc}: MemoryHigh={high:?}, want {want_high:?}"));
        }
        if swap != want_swap {
            out.push(format!("{svc}: MemorySwapMax={swap:?}, want {want_swap:?}"));
        }
    }
    let want_total = if supernode { 7296 - 768 + 1536 } else { 7296 };
    if out.is_empty() && total != want_total {
        out.push(format!(
            "MemoryMax adds up to {total} MiB, want {want_total}"
        ));
    }
    out
}

/// Strings that name a secret or where it lives.
const SECRET_WORDS: [&str; 3] = ["jwt", "nodekey", "/etc/ethswarm/credentials"];

/// Keys that would hand a unit a credential or an environment.
const CREDENTIAL_KEYS: [&str; 9] = [
    "LoadCredentialEncrypted",
    "SetCredential",
    "SetCredentialEncrypted",
    "ImportCredential",
    "Environment",
    "EnvironmentFile",
    "PassEnvironment",
    "UnsetEnvironment",
    "BindReadOnlyPaths",
];

fn credential_findings(units: &Units) -> Vec<String> {
    let mut out = Vec::new();
    for (name, text) in units {
        let want: Vec<&str> = CREDENTIALS
            .iter()
            .filter(|(svc, _)| unit_name(svc) == *name)
            .map(|(_, c)| *c)
            .collect();
        let got = values(text, "Service", "LoadCredential");
        if got != want {
            out.push(format!("{name}: LoadCredential={got:?}, want {want:?}"));
        }
        for (section, key, value) in entries(text) {
            if CREDENTIAL_KEYS.contains(&key.as_str()) {
                out.push(format!("{name}: [{section}] {key}={value} is not allowed"));
            }
            if key != "LoadCredential" {
                for word in SECRET_WORDS {
                    if value.to_ascii_lowercase().contains(word) {
                        out.push(format!("{name}: {key}={value} names {word}"));
                    }
                }
            }
        }
    }
    out
}

fn user_findings(units: &Units) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for svc in SERVICES {
        let text = service_unit(units, svc);
        let want = format!("ethswarm-{svc}");
        for key in ["User", "Group"] {
            match one(text, "Service", key) {
                Ok(v) if v == want => {}
                Ok(v) => out.push(format!("{svc}: {key}={v}, want {want}")),
                Err(e) => out.push(format!("{svc}: {e}")),
            }
        }
        for v in values(text, "Service", "User") {
            if !seen.insert(v.clone()) {
                out.push(format!("{svc}: User={v} is shared with another unit"));
            }
        }
        if !values(text, "Service", "DynamicUser").is_empty() {
            out.push(format!("{svc}: DynamicUser= is not allowed"));
        }
    }
    out
}

/// The units that list `group` as a supplementary group, by service.
fn caller_group_findings(units: &Units) -> Vec<String> {
    let mut out = Vec::new();
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for svc in SERVICES {
        let text = service_unit(units, svc);
        let lines = values(text, "Service", "SupplementaryGroups");
        if lines.len() > 1 {
            out.push(format!(
                "{svc}: SupplementaryGroups= appears {} times",
                lines.len()
            ));
        }
        let groups: Vec<String> = lines
            .iter()
            .flat_map(|l| l.split_whitespace())
            .map(str::to_owned)
            .collect();
        let mut sorted = groups.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != groups {
            out.push(format!(
                "{svc}: SupplementaryGroups={groups:?} not sorted and unique"
            ));
        }
        for g in groups {
            members.entry(g).or_default().insert(svc.to_owned());
        }
    }
    for (callee, callers) in CALLERS {
        let group = format!("ethswarm-{callee}");
        let got = members.remove(&group).unwrap_or_default();
        let want: BTreeSet<String> = callers.iter().map(|c| (*c).to_owned()).collect();
        if got != want {
            out.push(format!(
                "group {group}: members {got:?}, ARCH V-9 callers {want:?}"
            ));
        }
    }
    for (group, who) in members {
        out.push(format!(
            "{who:?} in group {group}, which is no service's group"
        ));
    }
    out
}

fn hardening_findings(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut keys: Vec<&str> = HARDENING.iter().map(|(k, _)| *k).collect();
    keys.dedup();
    for key in keys {
        let want: Vec<&str> = HARDENING
            .iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| *v)
            .collect();
        let got = values(text, "Service", key);
        if got != want {
            out.push(format!("{name}: {key}={got:?}, want {want:?}"));
        }
    }
    out
}

/// RestrictAddressFamilies= as in [`ADDRESS_FAMILIES`], and IP reach over every service unit
/// present (not only the eight): a [`NETWORK`] unit carries no IPAddressAllow=/IPAddressDeny=;
/// any other has AF_INET (for its /metrics bind), no family outside [`LOOPBACK_ADDRESS_FAMILIES`]
/// (so no AF_INET6 while the ruling has none) and exactly the [`LOOPBACK`] pair.
fn address_family_findings(units: &Units) -> Vec<String> {
    let mut out = Vec::new();
    for (svc, want) in ADDRESS_FAMILIES {
        match one(
            service_unit(units, svc),
            "Service",
            "RestrictAddressFamilies",
        ) {
            Ok(v) if v == want => {}
            Ok(v) => out.push(format!("{svc}: RestrictAddressFamilies={v}, want {want}")),
            Err(e) => out.push(format!("{svc}: {e}")),
        }
    }
    for (name, text) in units.iter().filter(|(n, _)| n.ends_with(".service")) {
        let svc = &name["ethswarm-".len()..name.len() - ".service".len()];
        let allow = values(text, "Service", "IPAddressAllow");
        let deny = values(text, "Service", "IPAddressDeny");
        if NETWORK.contains(&svc) {
            if !allow.is_empty() || !deny.is_empty() {
                out.push(format!(
                    "{name}: network unit with IPAddressAllow={allow:?} IPAddressDeny={deny:?}"
                ));
            }
            continue;
        }
        // The lines add up (systemd), so every family of every line counts.
        let lines = values(text, "Service", "RestrictAddressFamilies");
        let families: Vec<&str> = lines.iter().flat_map(|l| l.split_whitespace()).collect();
        // svc-runtime binds /metrics on 127.0.0.1 before READY=1 (crates/svc-runtime/src/
        // lifecycle.rs:192): without AF_INET socket() fails and the unit never gets ready.
        if !families.contains(&"AF_INET") {
            out.push(format!(
                "{name}: no AF_INET for /metrics on 127.0.0.1 ({lines:?})"
            ));
        }
        for family in families {
            if !LOOPBACK_ADDRESS_FAMILIES
                .split_whitespace()
                .any(|f| f == family)
            {
                out.push(format!(
                    "{name}: {family} on a loopback-only unit (the ruling: \
                     {LOOPBACK_ADDRESS_FAMILIES})"
                ));
            }
        }
        if allow != ["localhost"] || deny != ["any"] {
            out.push(format!(
                "{name}: IP without the loopback pair: IPAddressAllow={allow:?} \
                 IPAddressDeny={deny:?}, want exactly {LOOPBACK:?}"
            ));
        }
    }
    out
}

/// Type=notify, the timeouts and the restart policy.
const LIFECYCLE: [(&str, &str); 5] = [
    ("Type", "notify"),
    ("TimeoutStartSec", "90s"),
    ("TimeoutStopSec", "30s"),
    ("Restart", "on-failure"),
    ("RestartSec", "5s"),
];

fn lifecycle_findings(name: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (key, want) in LIFECYCLE {
        match one(text, "Service", key) {
            Ok(v) if v == want => {}
            Ok(v) => out.push(format!("{name}: {key}={v}, want {want}")),
            Err(e) => out.push(format!("{name}: {e}")),
        }
    }
    out
}

fn directory_findings(units: &Units) -> Vec<String> {
    let mut out = Vec::new();
    for svc in SERVICES {
        let text = service_unit(units, svc);
        let stateful = STATEFUL.contains(&svc);
        let want: [(&str, Option<String>); 4] = [
            ("RuntimeDirectory", Some(format!("ethswarm/cl-{svc}"))),
            ("RuntimeDirectoryMode", Some("0750".into())),
            (
                "StateDirectory",
                stateful.then(|| format!("ethswarm-{svc}")),
            ),
            ("StateDirectoryMode", stateful.then(|| "0700".into())),
        ];
        for (key, want) in want {
            let got = values(text, "Service", key);
            let want: Vec<String> = want.into_iter().collect();
            if got != want {
                out.push(format!("{svc}: {key}={got:?}, want {want:?}"));
            }
        }
    }
    out
}

/// After= from ruling 4 (After= only, following the start order) for each service.
fn after(svc: &str) -> BTreeSet<String> {
    let names: &[&str] = match svc {
        "verify" | "engine" => &[],
        "chain" => &["verify", "engine"],
        _ => &["chain"],
    };
    names.iter().map(|n| unit_name(n)).collect()
}

/// Keys that would make one unit's failure take another down, or pull it in.
const FORBIDDEN_DEPENDENCIES: [&str; 6] = [
    "Requires",
    "BindsTo",
    "Requisite",
    "Upholds",
    "PropagatesStopTo",
    "StopPropagatedFrom",
];

fn ordering_findings(units: &Units) -> Vec<String> {
    let mut out = Vec::new();
    for svc in SERVICES {
        let text = service_unit(units, svc);
        let got: BTreeSet<String> = values(text, "Unit", "After")
            .iter()
            .flat_map(|v| v.split_whitespace())
            .map(str::to_owned)
            .collect();
        if got != after(svc) {
            out.push(format!("{svc}: After={got:?}, want {:?}", after(svc)));
        }
        for (section, key, want) in [("Unit", "PartOf", TARGET), ("Install", "WantedBy", TARGET)] {
            if values(text, section, key) != [want] {
                out.push(format!("{svc}: [{section}] {key}= is not exactly {want}"));
            }
        }
    }
    for (name, text) in units {
        for (section, key, value) in entries(text) {
            if FORBIDDEN_DEPENDENCIES.contains(&key.as_str()) {
                out.push(format!("{name}: [{section}] {key}={value} (After= only)"));
            }
        }
    }
    match units.get(TARGET) {
        None => out.push(format!("no {TARGET}")),
        Some(text) => {
            let wants: Vec<String> = values(text, "Unit", "Wants")
                .iter()
                .flat_map(|v| v.split_whitespace())
                .map(str::to_owned)
                .collect();
            let want: Vec<String> = SERVICES.iter().map(|s| unit_name(s)).collect();
            if wants != want {
                out.push(format!("{TARGET}: Wants={wants:?}, want {want:?}"));
            }
            if values(text, "Install", "WantedBy") != ["multi-user.target"] {
                out.push(format!(
                    "{TARGET}: WantedBy= is not exactly multi-user.target"
                ));
            }
        }
    }
    out
}

// --- tests -----------------------------------------------------------------------------------

#[test]
fn generates_eight_services_and_the_target_in_start_order() {
    let names: Vec<String> = generate(&Config::default())
        .into_iter()
        .map(|u| u.name)
        .collect();
    let mut want: Vec<String> = SERVICES.iter().map(|s| unit_name(s)).collect();
    want.push(TARGET.into());
    assert_eq!(names, want);
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Compares `units` with the files in `dir` (and nothing else there but subdirectories), or
/// rewrites them with UPDATE_GOLDEN=1.
fn check_golden(dir: &Path, units: &Units) {
    if std::env::var("UPDATE_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::create_dir_all(dir).unwrap();
        for (name, text) in units {
            std::fs::write(dir.join(name), text).unwrap();
        }
    }
    let mut on_disk = BTreeSet::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            on_disk.insert(entry.file_name().into_string().unwrap());
        }
    }
    let generated: BTreeSet<String> = units.keys().cloned().collect();
    assert_eq!(on_disk, generated, "golden files in {}", dir.display());
    for (name, text) in units {
        let golden = std::fs::read_to_string(dir.join(name)).unwrap();
        assert!(
            golden == *text,
            "{name} differs from {} (UPDATE_GOLDEN=1 regenerates):\n--- golden\n{golden}\n--- generated\n{text}",
            dir.display()
        );
    }
}

#[test]
fn units_golden() {
    check_golden(&golden_dir(), &default_units());
    // The supernode variant changes cl-p2p's unit only.
    let default = default_units();
    let supernode: Units = supernode_units()
        .into_iter()
        .filter(|(name, text)| default[name] != *text)
        .collect();
    assert_eq!(
        supernode.keys().collect::<Vec<_>>(),
        [&unit_name("p2p")],
        "supernode changes only cl-p2p"
    );
    check_golden(&golden_dir().join("supernode"), &supernode);
}

#[test]
fn memory_max_matches_arch_section_9() {
    let sum: u64 = MEMORY_MAX_MIB.iter().map(|(_, m)| m).sum();
    assert_eq!(sum, 7296, "the oracle table itself");
    let units = default_units();
    assert_clean(memory_findings(&units, false));
    assert_clean(memory_findings(&supernode_units(), true));
    // The default profile is not the supernode one, and the other way round.
    assert_caught("default as supernode", memory_findings(&units, true));
    assert_caught(
        "supernode as default",
        memory_findings(&supernode_units(), false),
    );
    for (svc, line) in [
        ("chain", "MemoryMax=3G"),
        ("chain", "MemoryHigh=2G"),
        ("chain", "MemorySwapMax=0"),
        ("api", "MemoryMax=1G"),
        ("discv5", "MemoryMax=128M"),
    ] {
        assert_caught(
            line,
            memory_findings(&mutate(&units, svc, |t| without(t, line)), false),
        );
    }
    for (svc, extra) in [
        ("chain", "MemoryMax=4G"),
        ("store", "MemoryHigh=256M"),
        ("p2p", "MemorySwapMax=0"),
    ] {
        let mutated = mutate(&units, svc, |t| with(t, "Service", extra));
        assert_caught(extra, memory_findings(&mutated, false));
    }
}

#[test]
fn credentials_only_where_allowed() {
    let units = default_units();
    assert_clean(credential_findings(&units));
    assert_clean(credential_findings(&supernode_units()));
    for (svc, line) in CREDENTIALS {
        let line = format!("LoadCredential={line}");
        assert_caught(
            &line,
            credential_findings(&mutate(&units, svc, |t| without(t, &line))),
        );
    }
    for (svc, extra) in [
        (
            "chain",
            "LoadCredential=nodekey:/etc/ethswarm/credentials/nodekey",
        ),
        ("api", "LoadCredential=jwt:/etc/ethswarm/credentials/jwt"),
        (
            "engine",
            "LoadCredential=nodekey:/etc/ethswarm/credentials/nodekey",
        ),
        ("verify", "SetCredential=jwt:00"),
        ("chain", "ImportCredential=nodekey"),
        ("api", "Environment=JWT_SECRET=00"),
        ("sync", "EnvironmentFile=/etc/ethswarm/sync.env"),
        (
            "engine",
            "ExecStartPre=/bin/cat /etc/ethswarm/credentials/jwt",
        ),
    ] {
        let mutated = mutate(&units, svc, |t| with(t, "Service", extra));
        assert_caught(extra, credential_findings(&mutated));
    }
    // A secret on the command line.
    let mutated = mutate(&units, "engine", |t| {
        t.replace(
            "ExecStart=/usr/local/bin/cl-engine",
            "ExecStart=/usr/local/bin/cl-engine --jwt-secret /etc/ethswarm/credentials/jwt",
        )
    });
    assert_caught("ExecStart with the JWT path", credential_findings(&mutated));
}

/// Both profiles: `--supernode` rewrites cl-p2p's unit, so each gate runs on its units too.
fn profiles() -> [(&'static str, Units); 2] {
    [
        ("default", default_units()),
        ("supernode", supernode_units()),
    ]
}

/// `findings`, each prefixed with the profile it came from.
fn tagged(profile: &str, findings: Vec<String>) -> Vec<String> {
    findings
        .into_iter()
        .map(|f| format!("{profile}: {f}"))
        .collect()
}

#[test]
fn own_user_and_group_per_service() {
    for (profile, units) in profiles() {
        assert_clean(tagged(profile, user_findings(&units)));
        for svc in SERVICES {
            for key in ["User", "Group"] {
                let line = format!("{key}=ethswarm-{svc}");
                assert_caught(
                    &format!("{profile}: {line}"),
                    user_findings(&mutate(&units, svc, |t| without(t, &line))),
                );
            }
        }
        let shared = mutate(&units, "store", |t| {
            t.replace("User=ethswarm-store", "User=ethswarm-chain")
        });
        assert_caught(&format!("{profile}: a shared user"), user_findings(&shared));
        let root = mutate(&units, "api", |t| with(t, "Service", "User=root"));
        assert_caught(
            &format!("{profile}: User=root appended"),
            user_findings(&root),
        );
        let p2p_root = mutate(&units, "p2p", |t| {
            t.replace("User=ethswarm-p2p\n", "User=root\n")
        });
        assert_caught(
            &format!("{profile}: cl-p2p as root"),
            user_findings(&p2p_root),
        );
        let dynamic = mutate(&units, "sync", |t| with(t, "Service", "DynamicUser=yes"));
        assert_caught(
            &format!("{profile}: DynamicUser=yes"),
            user_findings(&dynamic),
        );
    }
}

#[test]
fn caller_groups_match_arch_table() {
    for (profile, units) in profiles() {
        assert_clean(tagged(profile, caller_group_findings(&units)));
        // Each caller's membership in each callee's group is load-bearing.
        for (callee, callers) in CALLERS {
            for caller in callers {
                let mutated = mutate(&units, caller, |t| {
                    let line = t
                        .lines()
                        .find(|l| l.starts_with("SupplementaryGroups="))
                        .unwrap()
                        .to_owned();
                    let groups: Vec<&str> = line["SupplementaryGroups=".len()..]
                        .split(' ')
                        .filter(|g| *g != format!("ethswarm-{callee}"))
                        .collect();
                    t.replace(&line, &format!("SupplementaryGroups={}", groups.join(" ")))
                });
                assert_caught(
                    &format!("{profile}: {caller} not in ethswarm-{callee}"),
                    caller_group_findings(&mutated),
                );
            }
        }
        let extra = mutate(&units, "verify", |t| {
            with(t, "Service", "SupplementaryGroups=ethswarm-engine")
        });
        assert_caught(
            &format!("{profile}: cl-verify in ethswarm-engine"),
            caller_group_findings(&extra),
        );
        // In place, sorted: cl-p2p in cl-engine's group (only cl-chain may call the EL side).
        let p2p_engine = mutate(&units, "p2p", |t| {
            t.replace(
                "SupplementaryGroups=ethswarm-chain ethswarm-discv5 ethswarm-store\n",
                "SupplementaryGroups=ethswarm-chain ethswarm-discv5 ethswarm-engine \
                 ethswarm-store\n",
            )
        });
        assert_caught(
            &format!("{profile}: cl-p2p in ethswarm-engine"),
            caller_group_findings(&p2p_engine),
        );
        let foreign = mutate(&units, "api", |t| {
            t.replace(
                "SupplementaryGroups=ethswarm-chain",
                "SupplementaryGroups=adm ethswarm-chain",
            )
        });
        assert_caught(
            &format!("{profile}: a group outside the node"),
            caller_group_findings(&foreign),
        );
    }
}

#[test]
fn hardening_on_every_unit() {
    for units in [default_units(), supernode_units()] {
        for svc in SERVICES {
            let name = unit_name(svc);
            let text = service_unit(&units, svc);
            assert_clean(hardening_findings(&name, text));
            for (key, value) in HARDENING {
                let line = format!("{key}={value}");
                assert_caught(&line, hardening_findings(&name, &without(text, &line)));
                let weaker = with(text, "Service", &format!("{key}=no"));
                assert_caught(
                    &format!("{key}=no after {line}"),
                    hardening_findings(&name, &weaker),
                );
            }
        }
    }
}

/// Whether `families` (one RestrictAddressFamilies= value) has `family`.
fn has(families: &str, family: &str) -> bool {
    families.split_whitespace().any(|f| f == family)
}

#[test]
fn address_families() {
    assert!(
        LOOPBACK_RULINGS.contains(&LOOPBACK_ADDRESS_FAMILIES),
        "LOOPBACK_ADDRESS_FAMILIES={LOOPBACK_ADDRESS_FAMILIES:?}, want one of {LOOPBACK_RULINGS:?}"
    );
    for units in [default_units(), supernode_units()] {
        assert_clean(address_family_findings(&units));
        for (svc, families) in ADDRESS_FAMILIES {
            let line = format!("RestrictAddressFamilies={families}");
            let removed = mutate(&units, svc, |t| without(t, &line));
            assert_caught(&line, address_family_findings(&removed));
            let widened = mutate(&units, svc, |t| {
                t.replace(&line, &format!("{line} AF_PACKET"))
            });
            assert_caught(
                &format!("{line} AF_PACKET"),
                address_family_findings(&widened),
            );
        }
    }
}

#[test]
fn loopback_only_ip_outside_the_network_services() {
    let loopback = format!("RestrictAddressFamilies={LOOPBACK_ADDRESS_FAMILIES}");
    for units in [default_units(), supernode_units()] {
        for svc in SERVICES.into_iter().filter(|s| !NETWORK.contains(s)) {
            for line in LOOPBACK {
                let removed = mutate(&units, svc, |t| without(t, line));
                assert_caught(
                    &format!("{svc} without {line}"),
                    address_family_findings(&removed),
                );
                let twice = mutate(&units, svc, |t| with(t, "Service", line));
                assert_caught(
                    &format!("{svc} with {line} twice"),
                    address_family_findings(&twice),
                );
            }
            // AF_INET with neither line: IP to anywhere.
            let open = mutate(&units, svc, |t| {
                without(&without(t, LOOPBACK[0]), LOOPBACK[1])
            });
            assert_caught(
                &format!("{svc}: AF_INET without the pair"),
                address_family_findings(&open),
            );
            // Widened: an address beyond loopback, or the deny list reset.
            for extra in [
                "IPAddressAllow=any",
                "IPAddressAllow=192.0.2.0/24",
                "IPAddressDeny=",
            ] {
                let widened = mutate(&units, svc, |t| with(t, "Service", extra));
                assert_caught(
                    &format!("{svc} with {extra}"),
                    address_family_findings(&widened),
                );
            }
            // AF_INET6, in the line or in a second one, unless the ruling grants it.
            if !has(LOOPBACK_ADDRESS_FAMILIES, "AF_INET6") {
                for v6 in [
                    mutate(&units, svc, |t| {
                        t.replace(&format!("{loopback}\n"), &format!("{loopback} AF_INET6\n"))
                    }),
                    mutate(&units, svc, |t| {
                        with(t, "Service", "RestrictAddressFamilies=AF_INET6")
                    }),
                ] {
                    assert_caught(
                        &format!("{svc} with AF_INET6"),
                        address_family_findings(&v6),
                    );
                }
            }
            // No AF_INET (AF_UNIX only, or AF_INET6 in its place): the /metrics bind fails.
            for narrowed in ["AF_UNIX", "AF_UNIX AF_INET6"] {
                let narrowed = mutate(&units, svc, |t| {
                    t.replace(
                        &format!("{loopback}\n"),
                        &format!("RestrictAddressFamilies={narrowed}\n"),
                    )
                });
                assert_caught(
                    &format!("{svc}: no AF_INET"),
                    address_family_findings(&narrowed),
                );
            }
        }
        for svc in NETWORK {
            for line in LOOPBACK {
                let confined = mutate(&units, svc, |t| with(t, "Service", line));
                assert_caught(
                    &format!("{svc} with {line}"),
                    address_family_findings(&confined),
                );
            }
        }
        // Any unit, not only the eight: a ninth loopback-only one with IP to anywhere, or with
        // AF_INET6 the ruling does not grant, is caught.
        let chain = &units[&unit_name("chain")];
        let mut ninth = units.clone();
        let open = without(&without(chain, LOOPBACK[0]), LOOPBACK[1]);
        ninth.insert(unit_name("extra"), open);
        assert_caught(
            "a ninth unit with IP to anywhere",
            address_family_findings(&ninth),
        );
        if !has(LOOPBACK_ADDRESS_FAMILIES, "AF_INET6") {
            let mut ninth = units.clone();
            let v6 = chain.replace(&format!("{loopback}\n"), &format!("{loopback} AF_INET6\n"));
            ninth.insert(unit_name("extra"), v6);
            assert_caught(
                "a ninth unit with AF_INET6",
                address_family_findings(&ninth),
            );
        }
    }
}

/// cl-chain runs through `svc_runtime::run_with`, which binds TCP `/metrics` on 127.0.0.1 before
/// READY=1 (crates/svc-runtime/src/lifecycle.rs:192, `telemetry::bind_metrics`). Under
/// `RestrictAddressFamilies=AF_UNIX` that socket(AF_INET) fails, loopback included, and the unit
/// loops on `Restart=`. units-verify.test.sh runs a real bind under these lines (systemd-run).
#[test]
fn chain_unit_permits_loopback_metrics_bind() {
    let units = default_units();
    let chain = service_unit(&units, "chain");
    let families = one(chain, "Service", "RestrictAddressFamilies").unwrap();
    assert!(
        has(&families, "AF_INET"),
        "cl-chain: RestrictAddressFamilies={families}: no AF_INET for /metrics on 127.0.0.1"
    );
    assert_eq!(families, LOOPBACK_ADDRESS_FAMILIES);
    assert_eq!(values(chain, "Service", "IPAddressAllow"), ["localhost"]);
    assert_eq!(values(chain, "Service", "IPAddressDeny"), ["any"]);
}

#[test]
fn notify_timeouts_restart() {
    let units = default_units();
    for svc in SERVICES {
        let name = unit_name(svc);
        let text = service_unit(&units, svc);
        assert_clean(lifecycle_findings(&name, text));
        for (key, value) in LIFECYCLE {
            let line = format!("{key}={value}");
            assert_caught(&line, lifecycle_findings(&name, &without(text, &line)));
        }
        let simple = text.replace("Type=notify", "Type=simple");
        assert_caught("Type=simple", lifecycle_findings(&name, &simple));
        let always = with(text, "Service", "Restart=always");
        assert_caught("a second Restart=", lifecycle_findings(&name, &always));
    }
}

#[test]
fn runtime_and_state_directories() {
    for (profile, units) in profiles() {
        assert_clean(tagged(profile, directory_findings(&units)));
        let removed = mutate(&units, "chain", |t| {
            without(t, "StateDirectory=ethswarm-chain")
        });
        assert_caught(
            &format!("{profile}: cl-chain without state"),
            directory_findings(&removed),
        );
        let loose = mutate(&units, "verify", |t| {
            t.replace("StateDirectoryMode=0700", "StateDirectoryMode=0750")
        });
        assert_caught(
            &format!("{profile}: a group-readable state directory"),
            directory_findings(&loose),
        );
        let extra = mutate(&units, "api", |t| {
            with(t, "Service", "StateDirectory=ethswarm-api")
        });
        assert_caught(
            &format!("{profile}: state for cl-api"),
            directory_findings(&extra),
        );
        let runtime = mutate(&units, "store", |t| without(t, "RuntimeDirectoryMode=0750"));
        assert_caught(
            &format!("{profile}: no RuntimeDirectoryMode"),
            directory_findings(&runtime),
        );
        let p2p_open = mutate(&units, "p2p", |t| {
            t.replace("RuntimeDirectoryMode=0750\n", "RuntimeDirectoryMode=0755\n")
        });
        assert_caught(
            &format!("{profile}: a world-readable cl-p2p socket directory"),
            directory_findings(&p2p_open),
        );
    }
}

#[test]
fn after_and_part_of_target() {
    let units = default_units();
    assert_clean(ordering_findings(&units));
    assert_clean(ordering_findings(&supernode_units()));
    for (svc, line) in [
        (
            "chain",
            "After=ethswarm-verify.service ethswarm-engine.service",
        ),
        ("api", "After=ethswarm-chain.service"),
        ("store", "PartOf=ethswarm.target"),
        ("sync", "WantedBy=ethswarm.target"),
    ] {
        assert_caught(
            line,
            ordering_findings(&mutate(&units, svc, |t| without(t, line))),
        );
    }
    for (svc, section, extra) in [
        ("store", "Unit", "Requires=ethswarm-chain.service"),
        ("p2p", "Unit", "BindsTo=ethswarm-chain.service"),
        ("engine", "Unit", "After=ethswarm-chain.service"),
        ("verify", "Install", "WantedBy=multi-user.target"),
    ] {
        let mutated = mutate(&units, svc, |t| with(t, section, extra));
        assert_caught(extra, ordering_findings(&mutated));
    }
    let mut no_api = units.clone();
    let target = without(&no_api[TARGET], "Wants=ethswarm-api.service");
    no_api.insert(TARGET.into(), target);
    assert_caught("the target without cl-api", ordering_findings(&no_api));
    let mut multi_user = units.clone();
    let target = without(&multi_user[TARGET], "WantedBy=multi-user.target");
    multi_user.insert(TARGET.into(), target);
    assert_caught(
        "the target not wanted at boot",
        ordering_findings(&multi_user),
    );
}

#[test]
fn rendering_is_deterministic() {
    let a = generate(&Config::default());
    let b = generate(&Config::default());
    assert_eq!(a.len(), 9, "eight services and the target");
    assert_eq!(a.len(), b.len());
    for (a, b) in a.iter().zip(&b) {
        assert_eq!((&a.name, &a.text), (&b.name, &b.text));
    }
    for unit in &a {
        let first = unit.text.lines().next().unwrap();
        assert!(
            first.starts_with("# Generated by `cl-node units`") && first.contains("Do not edit"),
            "{}: header {first:?}",
            unit.name
        );
        assert!(unit.text.ends_with('\n') && !unit.text.ends_with("\n\n"));
        for line in unit.text.lines() {
            assert!(
                line == line.trim_end() && !line.contains('\t') && !line.contains('\r'),
                "{}: {line:?}",
                unit.name
            );
            assert!(line.len() < 100, "{}: line too long: {line}", unit.name);
        }
    }
    // The network only names itself in the descriptions; everything else is the same.
    let hoodi = units(&Config::new("hoodi", false, Path::new("/usr/local/bin")).unwrap());
    for (name, text) in default_units() {
        let other = &hoodi[&name];
        for (l, r) in text.lines().zip(other.lines()) {
            if l != r {
                assert!(
                    l.starts_with("Description=") || l.starts_with("# Generated"),
                    "{name}: {l:?} vs {r:?}"
                );
                assert_eq!(l.replace("mainnet", "hoodi"), r);
            }
        }
    }
}

#[test]
fn exec_start_is_the_bin_dir_binary() {
    let config = Config::new("sepolia", false, Path::new("/opt/ethswarm/bin")).unwrap();
    let units = units(&config);
    for svc in SERVICES {
        assert_eq!(
            values(service_unit(&units, svc), "Service", "ExecStart"),
            [format!("/opt/ethswarm/bin/cl-{svc}")]
        );
    }
}

#[test]
fn config_rejects_values_systemd_would_interpret() {
    let bin = Path::new("/usr/local/bin");
    for network in ["", "Main net", "main%net", "a/b", "x\ny", &"a".repeat(65)] {
        assert!(
            Config::new(network, false, bin).is_err(),
            "network {network:?}"
        );
    }
    for ok in ["mainnet", "sepolia", "hoodi", "devnet-1", "gloas_a.2"] {
        assert!(Config::new(ok, false, bin).is_ok(), "network {ok:?}");
    }
    for dir in [
        "bin",
        "./bin",
        "/usr/local/bin/../sbin",
        "/opt/./bin",
        "/opt/my bin",
        "/opt/%n",
        "/opt/$HOME",
        "/opt/a\\b",
        "/opt/a\"b",
        "/opt/a;b",
        "/opt/a\nb",
        "/",
    ] {
        assert!(
            Config::new("mainnet", false, Path::new(dir)).is_err(),
            "bin_dir {dir:?}"
        );
    }
    assert!(Config::new("mainnet", false, Path::new("/opt/eth-swarm_1.0/bin/")).is_ok());
}

// --- the `cl-node units` command -------------------------------------------------------------

fn cl_node(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cl-node"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_writes_the_generated_units() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("units");
    let run = cl_node(&[
        "units",
        "--out",
        out.to_str().unwrap(),
        "--network",
        "hoodi",
    ]);
    assert!(run.status.success(), "{run:?}");
    let config = Config::new("hoodi", false, Path::new("/usr/local/bin")).unwrap();
    let want = units(&config);
    let mut got = Units::new();
    for entry in std::fs::read_dir(&out).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        got.insert(name, std::fs::read_to_string(entry.path()).unwrap());
    }
    assert_eq!(
        got, want,
        "exactly the generated files, no temporaries left"
    );

    // --supernode and --bin-dir reach the units; an existing regular file is replaced.
    let run = cl_node(&[
        "units",
        "--out",
        out.to_str().unwrap(),
        "--network",
        "hoodi",
        "--supernode",
        "--bin-dir",
        "/opt/ethswarm/bin",
    ]);
    assert!(run.status.success(), "{run:?}");
    let config = Config::new("hoodi", true, Path::new("/opt/ethswarm/bin")).unwrap();
    for (name, text) in units(&config) {
        assert_eq!(
            std::fs::read_to_string(out.join(&name)).unwrap(),
            text,
            "{name}"
        );
    }
}

#[test]
fn cli_refuses_to_replace_a_non_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere");
    std::fs::write(&elsewhere, "keep").unwrap();
    let out = dir.path().join("units");
    std::fs::create_dir(&out).unwrap();
    let link = out.join("ethswarm-chain.service");
    std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
    std::fs::create_dir(out.join(TARGET)).unwrap();
    let run = cl_node(&["units", "--out", out.to_str().unwrap()]);
    assert!(!run.status.success(), "{run:?}");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("not a regular file"), "{stderr}");
    assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "keep");
    assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
    assert!(out.join(TARGET).is_dir());
}

#[test]
fn cli_usage_errors() {
    for args in [
        &[][..],
        &["units"][..],
        &["units", "--out"][..],
        &["units", "--out", "/tmp/x", "--bogus"][..],
        &["units", "--out", "/tmp/x", "--network"][..],
        &["frobnicate"][..],
    ] {
        let run = cl_node(args);
        assert_eq!(run.status.code(), Some(2), "{args:?}: {run:?}");
        assert!(
            String::from_utf8_lossy(&run.stderr).contains("usage"),
            "{args:?}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("u");
    let out = out.to_str().unwrap();
    for args in [
        &["units", "--out", out, "--network", "bad net"][..],
        &["units", "--out", out, "--bin-dir", "relative/bin"][..],
    ] {
        let run = cl_node(args);
        assert_eq!(run.status.code(), Some(2), "{args:?}: {run:?}");
        assert!(!Path::new(out).exists(), "{args:?} wrote something");
    }
    let help = cl_node(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("cl-node units"));
}
