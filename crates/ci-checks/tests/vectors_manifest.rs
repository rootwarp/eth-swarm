//! The committed vector pins: every source pins its tag to a commit, every asset to a sha256,
//! and the example manifest stays identical to the real one.

mod common;

use common::workspace_root;
use std::fs;
use toml::Value;

const MANIFEST: &str = "testing/vectors.manifest.toml";
const EXAMPLE: &str = "testing/vectors.manifest.example.toml";

/// (source, tag, commit, file, sha256) pins that gate the vector set.
const PINS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "consensus-specs",
        "v1.7.0-beta.4",
        "aa16bb4c156184e9548a997d53efaf2a228a6304",
        "minimal.tar.gz",
        "26d09aea70c62ed235a120a95082d544ab1c2e6fe36bd35ea1bd5da62f3b7b68",
    ),
    (
        "consensus-specs",
        "v1.7.0-beta.4",
        "aa16bb4c156184e9548a997d53efaf2a228a6304",
        "mainnet.tar.gz",
        "67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c",
    ),
    (
        "ssz-specs",
        "v0.1.0",
        "7bce07ff7d51b1a3c66ff4e2bd3233ac248ede70",
        "ssz-test-vectors-v0.1.0.tar.gz",
        "e2a65f032b59835c26127295293ea1bc07d7ca0ea1fe0e4f1128dffed333f878",
    ),
    (
        "cryptography-specs",
        "v0.1.0",
        "ea1716be4f4a4835799e92d182e03b5c0bc2b6b9",
        "tests.zip",
        "eeb4893eb544f770810d9499007ebb0b9319431ea412bd54736e1c274da3d037",
    ),
    (
        "bls12-381-tests",
        "v0.1.2",
        "89ff3a86f1a9b89a555495f7535c853cda589320",
        "bls_tests_yaml.tar.gz",
        "a4ef909b6248395094949a3bcdeb4e1b5b999733d4436f2c5006edba99d29279",
    ),
];

fn load(rel: &str) -> Value {
    let text = fs::read_to_string(workspace_root().join(rel)).expect("read manifest");
    toml::from_str(&text).expect("manifest is TOML")
}

fn sources(m: &Value) -> &[Value] {
    m["source"].as_array().expect("[[source]] list")
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key:?} in {v}"))
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[test]
fn every_source_and_asset_is_pinned() {
    for s in sources(&load(MANIFEST)) {
        let name = str_field(s, "name");
        assert!(is_hex(str_field(s, "commit"), 40), "{name}: commit pin");
        let assets = s["asset"].as_array().expect("assets");
        assert!(!assets.is_empty(), "{name}: no assets");
        for a in assets {
            assert!(is_hex(str_field(a, "sha256"), 64), "{name}: sha256 pin");
        }
    }
}

#[test]
fn gate_pins_are_present() {
    let m = load(MANIFEST);
    for &(name, tag, commit, file, sha) in PINS {
        let source = sources(&m)
            .iter()
            .find(|s| str_field(s, "name") == name)
            .unwrap_or_else(|| panic!("source {name} missing"));
        assert_eq!(str_field(source, "tag"), tag, "{name} tag");
        assert_eq!(str_field(source, "commit"), commit, "{name} commit");
        let asset = source["asset"]
            .as_array()
            .expect("assets")
            .iter()
            .find(|a| str_field(a, "file") == file)
            .unwrap_or_else(|| panic!("{name}/{file} missing"));
        assert_eq!(str_field(asset, "sha256"), sha, "{name}/{file} sha256");
    }
}

#[test]
fn example_manifest_matches_the_real_one() {
    let root = workspace_root();
    assert_eq!(
        fs::read_to_string(root.join(EXAMPLE)).expect("example"),
        fs::read_to_string(root.join(MANIFEST)).expect("manifest"),
        "keep {EXAMPLE} identical to {MANIFEST}"
    );
}
