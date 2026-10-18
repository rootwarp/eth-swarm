use super::*;

const CHECKOUT: &str = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1";
const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

fn workflow(on: &str, permissions: &str, steps: &str) -> String {
    format!(
        "name: t\n{on}\n{permissions}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n{steps}"
    )
}

fn good() -> String {
    workflow(
        "on:\n  pull_request:",
        "permissions:\n  contents: read",
        &format!("      - uses: {CHECKOUT}\n      - run: echo ok\n"),
    )
}

fn with_step(step: &str) -> String {
    good().replace("      - run: echo ok\n", step)
}

fn with_job_perms(perms: &str) -> String {
    good().replace("    runs-on:", &format!("{perms}    runs-on:"))
}

fn reusable_job(extra: &str) -> String {
    format!(
        "{}\n  b:\n    uses: org/repo/.github/workflows/w.yml@{SHA} # v1\n{extra}",
        good().trim_end()
    )
}

fn assert_passes(body: &str) {
    let v = check_workflow("ci.yml", body);
    assert!(v.is_empty(), "{v:#?}\n---\n{body}");
}

fn assert_rejected(body: &str, needle: &str) {
    let v = check_workflow("ci.yml", body);
    assert!(
        v.iter().any(|v| v.message.contains(needle)),
        "want {needle:?}, got {v:#?}\n---\n{body}"
    );
}

#[test]
fn hardened_workflow_passes() {
    assert_passes(&good());
}

#[test]
fn local_actions_and_digest_pinned_images_are_allowed() {
    let digest = "ab".repeat(32); // synthetic: only its shape matters
    assert_passes(&workflow(
        "on: [pull_request]",
        "permissions: { contents: read }",
        &format!(
            "      - uses: ./.github/actions/setup\n      - uses: docker://alpine@sha256:{digest} # 3.20\n"
        ),
    ));
}

#[test]
fn invalid_or_non_mapping_yaml_is_rejected() {
    assert_rejected("on: [\n", "not valid YAML");
    assert_rejected("- a\n", "not a mapping");
    assert_rejected(
        &format!("{}---\nb: 1\n", good()),
        "exactly one YAML document",
    );
    assert_rejected("a: 1\na: 2\n", "not valid YAML");
}

#[test]
fn pull_request_target_is_rejected_in_every_trigger_form() {
    for on in [
        "on:\n  pull_request_target:",
        "on: pull_request_target",
        "on: [push, pull_request_target]",
        "on:\n  \"pull_request\\u005ftarget\":",
        "\"on\":\n  'pull_request_target':",
    ] {
        let body = good().replace("on:\n  pull_request:", on);
        assert_rejected(&body, "pull_request_target");
    }
}

#[test]
fn missing_or_malformed_triggers_are_rejected() {
    assert_rejected(&good().replace("on:\n  pull_request:\n", ""), "`on:`");
    assert_rejected(&good().replace("on:\n  pull_request:", "on: [1]"), "`on:`");
    assert_rejected(
        &good().replace("on:\n  pull_request:", "on: {1: x}"),
        "`on:`",
    );
}

#[test]
fn unpinned_uses_is_rejected_in_every_spelling() {
    for step in [
        "      - uses: actions/checkout@v7\n",
        "      - uses: actions/checkout@3d3c42e # v7.0.1\n",
        "      - \"uses\": actions/checkout@main # v7\n",
        "      - { uses: actions/checkout@main }\n",
        "      - uses: \"actions/checkout\\u0040main\"\n",
        "      - uses: docker://alpine:3.20 # 3.20\n",
        "      - uses: actions@0000000000000000000000000000000000000000 # v1\n",
    ] {
        assert_rejected(&with_step(step), "not pinned");
    }
}

#[test]
fn uses_must_be_a_string() {
    assert_rejected(&with_step("      - uses: [a]\n"), "not a string");
}

#[test]
fn reusable_workflow_must_be_pinned() {
    let body = format!(
        "{}\n  b:\n    uses: org/repo/.github/workflows/w.yml@main\n",
        good().trim_end()
    );
    assert_rejected(&body, "not pinned");
    assert_passes(&reusable_job(""));
}

#[test]
fn aliased_uses_is_still_checked() {
    let body = good().replace(
        "      - run: echo ok\n",
        "      - &bad { uses: actions/cache@v4 }\n      - *bad\n",
    );
    assert_rejected(&body, "not pinned");
}

#[test]
fn merge_keys_are_rejected() {
    let body = with_step("      - <<: { run: echo }\n        name: x\n");
    assert_rejected(&body, "merge keys");
}

#[test]
fn pinned_uses_needs_a_version_comment_on_every_line() {
    assert_rejected(
        &good().replace(CHECKOUT, &format!("'actions/checkout@{SHA}'")),
        "version comment",
    );
    assert_rejected(
        &good().replace(CHECKOUT, &format!("actions/checkout@{SHA} #")),
        "version comment",
    );
    assert_passes(&good().replace(CHECKOUT, &format!("\"actions/checkout@{SHA}\" # v7.0.1")));
    assert_passes(&with_step(&format!(
        "      - {{ uses: actions/checkout@{SHA} }} # v7.0.1\n"
    )));
}

#[test]
fn pinned_uses_that_cannot_be_found_verbatim_is_rejected() {
    let escaped = format!("actions/checkout\\u0040{SHA}");
    let body = good().replace(CHECKOUT, &format!("\"{escaped}\" # v7.0.1"));
    assert_rejected(&body, "verbatim");
}

#[test]
fn top_level_permissions_must_be_exactly_contents_read() {
    let body = good().replace("permissions:\n  contents: read\n", "");
    assert_rejected(&body, "top-level permissions");
    for perms in [
        "permissions: write-all",
        "permissions: read-all",
        "permissions:\n  contents: write",
        "permissions:\n  contents: read\n  pull-requests: write",
        "permissions: {}",
    ] {
        let body = good().replace("permissions:\n  contents: read", perms);
        assert_rejected(&body, "top-level permissions");
    }
}

#[test]
fn job_level_permissions_do_not_replace_the_top_level_block() {
    let body = with_job_perms("    permissions:\n      contents: read\n")
        .replace("permissions:\n  contents: read\n", "");
    assert_rejected(&body, "top-level permissions");
}

#[test]
fn job_level_write_permissions_are_rejected() {
    for perms in [
        "    permissions: { contents: write }\n",
        "    permissions: write-all\n",
        "    permissions:\n      contents: read\n      id-token: write\n",
        "    permissions:\n",
    ] {
        assert_rejected(&with_job_perms(perms), "job a: permissions");
    }
}

#[test]
fn job_level_read_or_none_permissions_are_allowed() {
    assert_passes(&with_job_perms(
        "    permissions:\n      contents: read\n      issues: none\n",
    ));
    assert_passes(&with_job_perms("    permissions: read-all\n"));
    assert_passes(&with_job_perms("    permissions: {}\n"));
}

#[test]
fn workflow_without_jobs_is_rejected() {
    assert_rejected(
        "on: pull_request\npermissions:\n  contents: read\n",
        "no jobs",
    );
}

#[test]
fn every_secrets_expression_form_is_rejected() {
    for expr in [
        "${{ secrets.DEPLOY }}",
        "${{ toJSON(secrets) }}",
        "${{ secrets ['DEPLOY'] }}",
        "${{secrets.DEPLOY}}",
        "${{ github.token || secrets.X }}",
    ] {
        let body = with_step(&format!(
            "      - run: echo ok\n        env:\n          T: {expr}\n"
        ));
        assert_rejected(&body, "secrets are forbidden");
    }
}

#[test]
fn secrets_in_a_comment_line_are_rejected() {
    let body = with_step("      - run: |\n          # ${{ secrets.DEPLOY }}\n          echo ok\n");
    assert_rejected(&body, "secrets are forbidden");
    let yaml_comment = format!("# ${{{{ secrets.X }}}}\n{}", good());
    assert_rejected(&yaml_comment, "secrets are forbidden");
}

#[test]
fn escaped_secrets_expression_is_rejected() {
    let body = with_step("      - run: \"\\u0024{{ secrets.X }}\"\n");
    assert_rejected(&body, "decoded string");
}

#[test]
fn secrets_key_with_a_value_is_rejected() {
    for extra in [
        "    secrets: inherit\n",
        "    secrets: 'inherit'\n",
        "    secrets:\n      token: x\n",
    ] {
        assert_rejected(&reusable_job(extra), "secrets:");
    }
    assert_passes(&reusable_job("    secrets: {}\n"));
}

#[test]
fn identifiers_containing_secrets_are_not_the_secrets_context() {
    let body = with_step(
        "      - run: echo ok\n        env:\n          T: ${{ inputs.my_secrets }} ${{ env.secrets-dir }}\n",
    );
    assert_passes(&body);
}

#[test]
fn plain_mentions_of_secrets_are_allowed() {
    assert_passes(&format!("# never read secrets.ANYTHING here\n{}", good()));
}

#[test]
fn secrets_outside_pull_request_workflows_are_allowed() {
    let body = good()
        .replace(
            "on:\n  pull_request:",
            "on:\n  schedule:\n    - cron: '0 3 * * *'",
        )
        .replace(
            "      - run: echo ok\n",
            "      - run: echo ok\n        env:\n          TOKEN: ${{ secrets.NIGHTLY }}\n",
        );
    assert_passes(&body);
}

#[test]
fn violations_render_with_file_and_line() {
    let v = check_workflow("ci.yml", &with_step("      - uses: actions/checkout@v7\n"));
    let shown: Vec<String> = v.iter().map(ToString::to_string).collect();
    assert!(
        shown
            .iter()
            .any(|s| s.starts_with("ERROR ci.yml:11: uses: actions/checkout@v7")),
        "{shown:?}"
    );
    let v = check_workflow("ci.yml", "on: [\n");
    assert!(v[0].to_string().starts_with("ERROR ci.yml: not valid YAML"));
}

#[test]
fn secrets_context_is_matched_case_insensitively() {
    for expr in [
        "${{ SECRETS.TOKEN }}",
        "${{ toJSON(Secrets) }}",
        "${{ toJSON(SeCrEtS) }}",
    ] {
        let body = with_step(&format!(
            "      - run: echo ok\n        env:\n          T: {expr}\n"
        ));
        assert_rejected(&body, "secrets are forbidden");
    }
}

#[test]
fn closing_braces_inside_a_string_do_not_end_the_raw_scan() {
    let body = with_step(
        "      - run: echo ok\n        env:\n          T: ${{ '}}' && secrets.DEPLOY_TOKEN }}\n",
    );
    assert_rejected(&body, "secrets are forbidden");
}

#[test]
fn closing_braces_inside_a_string_do_not_end_the_decoded_scan() {
    let body = with_step("      - run: \"\\u0024{{ '}}' && secrets.X }}\"\n");
    assert_rejected(&body, "decoded string");
}

#[test]
fn version_comment_must_be_on_the_uses_line_itself() {
    let escaped = format!("actions/checkout@\\x33{}", &SHA[1..]);
    let body = good().replace(
        &format!("- uses: {CHECKOUT}"),
        &format!("# actions/checkout@{SHA} # v7.0.1\n      - uses: \"{escaped}\""),
    );
    assert_rejected(&body, "verbatim");
}

#[test]
fn each_pinned_uses_needs_its_own_verbatim_line() {
    let escaped = format!("actions/checkout@\\x33{}", &SHA[1..]);
    let body = with_step(&format!("      - uses: \"{escaped}\"\n"));
    assert_rejected(&body, "verbatim");
}

#[test]
fn secrets_in_an_if_without_expression_braces_are_rejected() {
    for cond in [
        "secrets.TOKEN != ''",
        "Secrets.TOKEN != ''",
        "SECRETS.token",
        "toJSON(secrets) != '{}'",
        "toJSON(SeCrEtS) != '{}'",
        "github.event_name == 'push' && secrets.X",
        "\"\\u0073ecrets.X != ''\"",
    ] {
        let step = with_step(&format!("      - if: {cond}\n        run: echo ok\n"));
        assert_rejected(&step, "if:");
        let job = good().replace("    runs-on:", &format!("    if: {cond}\n    runs-on:"));
        assert_rejected(&job, "job a: if:");
    }
}

#[test]
fn if_without_the_secrets_context_is_allowed() {
    assert_passes(&with_step(
        "      - if: github.event_name == 'pull_request' && inputs.my_secrets\n        run: echo ok\n",
    ));
    assert_passes(&good().replace("    runs-on:", "    if: true\n    runs-on:"));
}

#[test]
fn uses_text_on_a_run_or_name_line_is_not_a_uses_line() {
    let escaped = format!("actions/checkout\\x40{SHA}");
    for decoy in [
        format!("      - run: echo uses actions/checkout@{SHA} # v7.0.1\n"),
        format!("      - name: uses actions/checkout@{SHA} # v7.0.1\n        run: echo\n"),
        format!("      - run: 'echo {{ uses: actions/checkout@{SHA} }}' # v7.0.1\n"),
        format!("      - {{ name: x, uses: actions/checkout@{SHA} }} # v7.0.1\n"),
        format!("      - -uses: actions/checkout@{SHA} # v7.0.1\n"),
    ] {
        let body = good().replace(
            &format!("      - uses: {CHECKOUT}\n"),
            &format!("{decoy}      - uses: \"{escaped}\"\n"),
        );
        assert_rejected(&body, "verbatim");
    }
}

#[test]
fn uses_lines_inside_a_block_scalar_are_not_uses_lines() {
    let escaped = format!("actions/checkout\\x40{SHA}");
    let decoy = format!("- uses: actions/checkout@{SHA} # v7.0.1");
    for block in [
        format!("      - run: |\n          {decoy}\n"),
        format!("      - name: |\n          {decoy}\n        run: echo\n"),
        format!("      - run: >-\n          {decoy}\n"),
        format!("      - run: |2\n            {decoy}\n"),
        format!("      - env:\n          X: |\n            {decoy}\n        run: echo\n"),
    ] {
        let body = good().replace(
            &format!("      - uses: {CHECKOUT}\n"),
            &format!("{block}      - uses: \"{escaped}\"\n"),
        );
        assert_rejected(&body, "verbatim");
    }
}

#[test]
fn uses_values_are_located_by_the_parser() {
    let text = "a:\n  - uses: x\n  - { k: uses, uses: \"y\" }\n  - [uses, z]\n  - &q uses: *q\nb: |\n  uses: w\n";
    assert_eq!(
        UsesValues::of(text),
        [(2, "x".to_owned()), (3, "y".to_owned())]
    );
    assert!(UsesValues::of("a: [\n").is_empty());
}

#[test]
fn a_uses_key_after_a_block_scalar_still_counts() {
    assert_passes(&good().replace(
        &format!("      - uses: {CHECKOUT}\n"),
        &format!("      - run: |\n          echo {SHA}\n      - uses: {CHECKOUT}\n"),
    ));
    assert_passes(&with_step(&format!(
        "      - name: |\n          uses\n        uses: {CHECKOUT}\n"
    )));
}

#[test]
fn quoted_keys_and_spaced_colons_are_still_uses_lines() {
    for line in [
        format!("      - \"uses\": actions/checkout@{SHA} # v7.0.1\n"),
        format!("      - 'uses' : 'actions/checkout@{SHA}' # v7.0.1\n"),
        format!("      -   {{uses: \"actions/checkout@{SHA}\"}} # v7.0.1\n"),
    ] {
        assert_passes(&good().replace(&format!("      - uses: {CHECKOUT}\n"), &line));
    }
}

#[test]
fn raw_secrets_error_explains_the_coarse_match() {
    for expr in [
        "${{ github.sha }}  # no secrets here",
        "${{ inputs.secrets }}",
        "${{ github.workspace }}/secrets",
    ] {
        let body = with_step(&format!(
            "      - run: echo ok\n        env:\n          T: {expr}\n"
        ));
        assert_rejected(&body, "(any `secrets` word after `${{` on the line counts)");
    }
}

#[test]
fn setting_fuzz_lock_cargo_is_rejected_at_every_level() {
    let step_env = "      - run: bash scripts/check-fuzz-lock.sh\n        env:\n          FUZZ_LOCK_CARGO: /usr/bin/true\n";
    for body in [
        good().replace(
            "permissions:\n",
            "env:\n  FUZZ_LOCK_CARGO: /usr/bin/true\npermissions:\n",
        ),
        with_job_perms("    env:\n      FUZZ_LOCK_CARGO: /usr/bin/true\n"),
        with_step(step_env),
        with_step("      - run: FUZZ_LOCK_CARGO=/usr/bin/true bash scripts/check-fuzz-lock.sh\n"),
        with_step("      - run: echo FUZZ_LOCK_CARGO=/usr/bin/true >> \"$GITHUB_ENV\"\n"),
        with_step("      - run: |\n          export FUZZ_LOCK_CARGO=/usr/bin/true\n          bash scripts/check-fuzz-lock.sh\n"),
        with_step(&step_env.replace("FUZZ_LOCK_CARGO", "fuzz_lock_cargo")),
        with_step(&step_env.replace("FUZZ_LOCK_CARGO:", "\"FUZZ_LOCK\\x5FCARGO\":")),
    ] {
        assert_rejected(&body, "FUZZ_LOCK_CARGO");
    }
}

#[test]
fn fuzz_lock_cargo_is_rejected_outside_pull_request_workflows_too() {
    let body = with_step(
        "      - run: bash scripts/check-fuzz-lock.sh\n        env:\n          FUZZ_LOCK_CARGO: /usr/bin/true\n",
    )
    .replace(
        "on:\n  pull_request:",
        "on:\n  schedule:\n    - cron: '0 3 * * *'",
    );
    assert_rejected(&body, "FUZZ_LOCK_CARGO");
}

#[test]
fn fuzz_lock_cargo_violation_names_its_line() {
    let body = with_step(
        "      - run: bash scripts/check-fuzz-lock.sh\n        env:\n          FUZZ_LOCK_CARGO: /usr/bin/true\n",
    );
    let shown: Vec<String> = check_workflow("ci.yml", &body)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        shown
            .iter()
            .any(|s| s.starts_with("ERROR ci.yml:13: FUZZ_LOCK_CARGO")),
        "{shown:?}\n---\n{body}"
    );
}

#[test]
fn the_lock_check_without_fuzz_lock_cargo_is_allowed() {
    assert_passes(&with_step(
        "      - run: bash scripts/check-fuzz-lock.sh\n        env:\n          CARGO_NET_OFFLINE: 'true'\n",
    ));
    // A comment is not a setting.
    assert_passes(&format!(
        "# scripts/check-fuzz-lock.sh: FUZZ_LOCK_CARGO is for its tests only\n{}",
        good()
    ));
}
