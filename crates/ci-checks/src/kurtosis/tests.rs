use super::*;

const D64: &str = "5b666c7b7d18454828a205bd94edd76c8d19068d62365c0fa676980cdd548bdd";

fn pinned(image: &str) -> String {
    format!("{image}@sha256:{D64}")
}

/// An args file that passes: one participant with all three images pinned, one additional
/// service with its image pinned, and the pinned genesis generator.
fn good() -> String {
    let lh = pinned("ethpandaops/lighthouse:unstable-c8ddac7");
    format!(
        "participants:\n  - el_type: geth\n    el_image: {geth}\n    cl_type: lighthouse\n    \
         cl_image: {lh}\n    vc_image: {lh}\nnetwork_params:\n  preset: minimal\n\
         additional_services:\n  - spamoor\nspamoor_params:\n  image: {spamoor}\n\
         ethereum_genesis_generator_params:\n  image: {gen}\n",
        geth = pinned("ethereum/client-go:v1.17.8"),
        spamoor = pinned("ethpandaops/spamoor:master-ca48df9"),
        gen = pinned("ethpandaops/ethereum-genesis-generator:6.2.6"),
    )
}

fn messages(text: &str) -> Vec<String> {
    check_args_file("t.yaml", text)
        .into_iter()
        .map(|v| v.message)
        .collect()
}

fn assert_flags(text: &str, needle: &str) {
    let found = messages(text);
    assert!(
        found.iter().any(|m| m.contains(needle)),
        "want a violation containing {needle:?}, got {found:?}\n--- file\n{text}"
    );
}

#[test]
fn good_file_passes() {
    assert_eq!(messages(&good()), Vec::<String>::new());
}

#[test]
fn pinned_references() {
    for r in [
        pinned("sigp/lighthouse:v8.3.0-rc.0"),
        pinned("ghcr.io/paradigmxyz/reth:v2.7.0"),
        pinned("registry.example:5000/team/reth:v1"),
        pinned("geth:latest"),
        pinned("ethpandaops/lodestar:unstable_b3beff2"),
    ] {
        assert!(is_image_pinned(&r), "{r} should count as pinned");
    }
}

#[test]
fn unpinned_references() {
    let short = format!("ethereum/client-go:v1.17.8@sha256:{}", &D64[..12]);
    let upper = format!("ethereum/client-go:v1.17.8@sha256:{}", D64.to_uppercase());
    let long = format!("ethereum/client-go:v1.17.8@sha256:{D64}a");
    let tag_too_long = pinned(&format!("ethereum/client-go:{}", "v".repeat(129)));
    for r in [
        "ethereum/client-go:v1.17.8".to_owned(),
        "ethereum/client-go:latest".to_owned(),
        "ethereum/client-go".to_owned(),
        String::new(),
        // A digest without a tag: the tag records which release the digest is.
        format!("ethereum/client-go@sha256:{D64}"),
        // A registry port is not a tag.
        pinned("registry.example:5000/team/reth"),
        short,
        upper,
        long,
        tag_too_long,
        format!("ethereum/client-go:v1.17.8@sha512:{D64}"),
        format!("ethereum/client-go:v1.17.8@sha256:{D64} "),
        format!(" ethereum/client-go:v1.17.8@sha256:{D64}"),
        pinned("Ethereum/client-go:v1.17.8"),
        pinned("ethereum//client-go:v1.17.8"),
        pinned("ethereum/client-go/:v1.17.8"),
        pinned("-ethereum/client-go:v1.17.8"),
        pinned("ethereum/client-go:.v1"),
        pinned("ethereum/client-go:v1@x"),
        pinned("host:port/client-go:v1"),
        pinned("host:5000:6000/client-go:v1"),
        pinned("ethereum/client go:v1"),
    ] {
        assert!(!is_image_pinned(&r), "{r:?} should not count as pinned");
    }
}

#[test]
fn every_image_key_anywhere_is_checked() {
    let cases = [
        (
            "cl_image: {lh}",
            "cl_image: sigp/lighthouse:latest",
            "participants[0].cl_image",
        ),
        (
            "el_image: {geth}",
            "el_image: ethereum/client-go:latest",
            "participants[0].el_image",
        ),
        (
            "vc_image: {lh}",
            "vc_image: \"\"",
            "participants[0].vc_image",
        ),
    ];
    let lh = pinned("ethpandaops/lighthouse:unstable-c8ddac7");
    let geth = pinned("ethereum/client-go:v1.17.8");
    for (from, to, path) in cases {
        let from = from.replace("{lh}", &lh).replace("{geth}", &geth);
        let text = good().replacen(&from, to, 1);
        assert_ne!(text, good(), "fixture did not change for {path}");
        assert_flags(&text, path);
    }
    // A service image, at any depth, under `image` or any `*_image` key, in any letter case.
    assert_flags(
        &format!("{}dora_params:\n  image: ethpandaops/dora:latest\n", good()),
        "dora_params.image",
    );
    assert_flags(
        &format!(
            "{}mev_params:\n  mev_relay_image: flashbots/relay:main\n",
            good()
        ),
        "mev_params.mev_relay_image",
    );
    assert_flags(
        &format!(
            "{}x:\n  - y:\n      Blobber_IMAGE: ethpandaops/blobber:1.1.0\n",
            good()
        ),
        "x[0].y.Blobber_IMAGE",
    );
}

#[test]
fn flow_mappings_quotes_and_aliases_cannot_hide_an_image() {
    assert_flags(
        &format!(
            "{}dora_params: {{image: 'ethpandaops/dora:latest'}}\n",
            good()
        ),
        "dora_params.image",
    );
    assert_flags(
        &format!(
            "{}dora_params:\n  \"image\": \"ethpandaops/dora:latest\"\n",
            good()
        ),
        "dora_params.image",
    );
    assert_flags(
        &format!(
            "{}x: &floating ethpandaops/dora:latest\ndora_params:\n  image: *floating\n",
            good()
        ),
        "dora_params.image",
    );
}

#[test]
fn non_string_image_values_fail() {
    for value in ["null", "~", "", "42", "[a, b]", "{a: b}", "true"] {
        let text = format!("{}dora_params:\n  image: {value}\n", good());
        assert_flags(&text, "dora_params.image");
    }
}

#[test]
fn participants_must_set_every_client_image() {
    let lh = pinned("ethpandaops/lighthouse:unstable-c8ddac7");
    let geth = pinned("ethereum/client-go:v1.17.8");
    for (line, key) in [
        (format!("    el_image: {geth}\n"), "el_image"),
        (format!("    cl_image: {lh}\n"), "cl_image"),
        (format!("    vc_image: {lh}\n"), "vc_image"),
    ] {
        let text = good().replacen(&line, "", 1);
        assert_ne!(text, good(), "fixture did not drop {key}");
        assert_flags(&text, &format!("participants[0] does not set {key}"));
    }
}

#[test]
fn participants_without_el_or_separate_vc_need_no_such_image() {
    let lh = pinned("ethpandaops/lighthouse:unstable-c8ddac7");
    let geth = pinned("ethereum/client-go:v1.17.8");
    let no_el = good()
        .replacen("el_type: geth", "el_type: None", 1)
        .replacen(&format!("    el_image: {geth}\n"), "", 1);
    assert_eq!(messages(&no_el), Vec::<String>::new());
    let no_vc = good().replacen(
        &format!("    vc_image: {lh}\n"),
        "    use_separate_vc: false\n",
        1,
    );
    assert_eq!(messages(&no_vc), Vec::<String>::new());
}

#[test]
fn participants_matrix_entries_must_set_their_image() {
    let geth = pinned("ethereum/client-go:v1.17.8");
    let lh = pinned("ethpandaops/lighthouse:unstable-c8ddac7");
    let matrix = format!(
        "participants_matrix:\n  el:\n    - el_type: geth\n      el_image: {geth}\n  \
         cl:\n    - cl_type: lighthouse\n      cl_image: {lh}\n  vc:\n    - vc_type: lighthouse\n      \
         vc_image: {lh}\n"
    );
    let base = format!("{}{matrix}", good());
    assert_eq!(messages(&base), Vec::<String>::new());
    for (line, path) in [
        (
            format!("      el_image: {geth}\n"),
            "participants_matrix.el[0] does not set el_image",
        ),
        (
            format!("      cl_image: {lh}\n"),
            "participants_matrix.cl[0] does not set cl_image",
        ),
        (
            format!("      vc_image: {lh}\n"),
            "participants_matrix.vc[0] does not set vc_image",
        ),
    ] {
        let text = base.replacen(&line, "", 1);
        assert_ne!(text, base);
        assert_flags(&text, path);
    }
}

#[test]
fn additional_services_must_pin_their_image() {
    assert_flags(
        &format!(
            "{}additional_services:\n  - spamoor\n  - dora\n",
            good().replace("additional_services:\n  - spamoor\n", "")
        ),
        "additional service dora: dora_params.image is not set",
    );
    assert_flags(
        &good()
            .replace("spamoor_params:\n", "spamoor_params:\n  max_cpu: 1000\n")
            .replacen(
                &format!(
                    "  image: {}\n",
                    pinned("ethpandaops/spamoor:master-ca48df9")
                ),
                "",
                1,
            ),
        "additional service spamoor: spamoor_params.image is not set",
    );
    assert_flags(
        &good().replace(
            "additional_services:\n  - spamoor\n",
            "additional_services: spamoor\n",
        ),
        "additional_services is not a list of service names",
    );
    assert_flags(
        &good().replace(
            "additional_services:\n  - spamoor\n",
            "additional_services:\n  - [spamoor]\n",
        ),
        "additional_services[0] is not a service name",
    );
}

#[test]
fn genesis_generator_image_must_be_set() {
    let text = good().replacen(
        &format!(
            "ethereum_genesis_generator_params:\n  image: {}\n",
            pinned("ethpandaops/ethereum-genesis-generator:6.2.6")
        ),
        "",
        1,
    );
    assert_ne!(text, good());
    assert_flags(&text, "ethereum_genesis_generator_params.image is not set");
}

#[test]
fn malformed_files_fail() {
    assert_flags("participants: [\n", "not valid YAML");
    assert_flags("a: 1\na: 2\n", "not valid YAML");
    assert_flags("a: 1\n---\nb: 2\n", "exactly one YAML document");
    assert_flags("", "exactly one YAML document");
    assert_flags("- a\n", "not a mapping");
    assert_flags(
        &format!("{}base: &b {{el_type: geth}}\nmore:\n  <<: *b\n", good()),
        "merge keys",
    );
    assert_flags(
        &good().replacen("participants:\n", "participants: 3\nunused:\n", 1),
        "participants is not a list",
    );
    assert_flags(
        &good().replacen(
            "participants:\n  - el_type",
            "participants:\n  - 3\n  - el_type",
            1,
        ),
        "participants[0] is not a mapping",
    );
}

#[test]
fn violations_name_the_file() {
    let out = check_args_file("gloas.yaml", "- a\n");
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].to_string(),
        "ERROR gloas.yaml: args file is not a mapping"
    );
}

#[test]
fn check_dir_reads_every_yaml_file_and_fails_closed() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("kurtosis");
    std::fs::create_dir(&dir).unwrap();
    assert!(check_dir(&dir).unwrap_err().contains("no args files"));
    std::fs::write(dir.join("a.yaml"), good()).unwrap();
    std::fs::write(
        dir.join("b.yml"),
        "dora_params:\n  image: ethpandaops/dora:latest\n",
    )
    .unwrap();
    std::fs::write(dir.join("notes.md"), "image: x\n").unwrap();
    let report = check_dir(&dir).unwrap();
    assert_eq!(report.files, 2);
    assert!(
        report.violations.iter().all(|v| v.file == "b.yml"),
        "{:?}",
        report.violations
    );
    assert!(!report.violations.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(check_dir(&dir).is_err());
}

/// `good()` without its `participants` list.
fn without_participants() -> String {
    let start = good().find("participants:\n").unwrap();
    let end = good().find("network_params:\n").unwrap();
    let mut text = good();
    text.replace_range(start..end, "");
    text
}

/// A `participants_matrix` with one pinned EL, CL and VC entry.
fn matrix() -> String {
    let geth = pinned("ethereum/client-go:v1.17.8");
    let lh = pinned("ethpandaops/lighthouse:unstable-c8ddac7");
    format!(
        "participants_matrix:\n  el:\n    - el_type: geth\n      el_image: {geth}\n  \
         cl:\n    - cl_type: lighthouse\n      cl_image: {lh}\n  vc:\n    - vc_type: lighthouse\n      \
         vc_image: {lh}\n"
    )
}

#[test]
fn a_file_without_participants_or_a_matrix_fails() {
    // The package turns a missing `participants` into one default participant, which runs the
    // default (floating) client images.
    let text = without_participants();
    assert!(
        !text.contains("participants"),
        "fixture still has participants"
    );
    assert_flags(&text, "neither participants nor participants_matrix is set");
}

#[test]
fn an_empty_participant_set_fails() {
    assert_flags(
        &format!("{}participants: []\n", without_participants()),
        "no participant",
    );
    for empty in [
        "participants_matrix: {}\n".to_owned(),
        matrix().replacen("  cl:\n", "  cl: []\n  unused:\n", 1),
        matrix().replacen("  el:\n", "  el: []\n  unused:\n", 1),
        format!("{}  count: 0\n", matrix()),
    ] {
        assert_flags(
            &format!("{}{empty}", without_participants()),
            "participants_matrix yields no participant",
        );
    }
    assert_flags(
        &format!("{}{}  count: two\n", without_participants(), matrix()),
        "participants_matrix.count is not an integer",
    );
}

#[test]
fn either_participant_form_alone_passes() {
    assert_eq!(messages(&good()), Vec::<String>::new());
    let matrix_only = format!("{}{}", without_participants(), matrix());
    assert_eq!(messages(&matrix_only), Vec::<String>::new());
    let counted = format!("{matrix_only}  count: 2\n");
    assert_eq!(messages(&counted), Vec::<String>::new());
    // An empty list next to a matrix that yields participants is fine.
    let both = format!("{}participants: []\n{}", without_participants(), matrix());
    assert_eq!(messages(&both), Vec::<String>::new());
}

#[test]
fn blockscout_must_pin_every_image_key() {
    let only_image = format!(
        "{}blockscout_params:\n  image: {}\n",
        good().replacen(
            "additional_services:\n  - spamoor\n",
            "additional_services:\n  - spamoor\n  - blockscout\n",
            1,
        ),
        pinned("ghcr.io/blockscout/blockscout:9.0.2"),
    );
    let found = messages(&only_image);
    for key in ["verif_image", "frontend_image"] {
        assert_flags(
            &only_image,
            &format!("additional service blockscout: blockscout_params.{key} is not set"),
        );
    }
    assert!(
        !found.iter().any(|m| m.contains("blockscout_params.image ")),
        "{found:?}"
    );
    let all = format!(
        "{only_image}  verif_image: {}\n  frontend_image: {}\n",
        pinned("ghcr.io/blockscout/smart-contract-verifier:v1.9.0"),
        pinned("ghcr.io/blockscout/frontend:v2.0.0"),
    );
    assert_eq!(messages(&all), Vec::<String>::new());
}

#[test]
fn a_service_without_known_image_keys_fails_closed() {
    for svc in ["forky", "zkboost", "prometheus_grafana", "made_up"] {
        let text = good().replacen(
            "additional_services:\n  - spamoor\n",
            &format!(
                "additional_services:\n  - spamoor\n  - {svc}\n{svc}_params:\n  image: {}\n",
                pinned("x/y:z")
            ),
            1,
        );
        assert_flags(
            &text,
            &format!("additional service {svc}: its image keys are not known"),
        );
    }
}

#[test]
fn every_known_service_names_its_image_keys() {
    let services: Vec<&str> = SERVICE_IMAGE_KEYS.iter().map(|(s, _)| *s).collect();
    let mut sorted = services.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(services, sorted, "SERVICE_IMAGE_KEYS is sorted and unique");
    for (svc, keys) in SERVICE_IMAGE_KEYS {
        assert!(!keys.is_empty(), "{svc} has no image keys");
        assert!(keys.iter().all(|k| is_image_key(k)), "{svc}: {keys:?}");
    }
    for svc in ["buildoor", "dora", "spamoor"] {
        assert!(services.contains(&svc), "the devnet's {svc} is listed");
    }
}
