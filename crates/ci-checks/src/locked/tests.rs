use super::*;

fn findings(value: &str) -> Vec<String> {
    check_run(value, &[])
        .into_iter()
        .map(|f| f.message)
        .collect()
}

fn assert_passes(value: &str) {
    let found = findings(value);
    assert!(found.is_empty(), "{found:#?}\n--- run value\n{value}");
}

fn assert_rejected(value: &str, needle: &str) {
    let found = findings(value);
    assert!(
        found.iter().any(|m| m.contains(needle)),
        "want a finding containing {needle:?}, got {found:#?}\n--- run value\n{value}"
    );
}

/// A workflow whose one step has the given step lines (indented as a sequence entry).
fn workflow(step: &str) -> String {
    format!(
        "on: pull_request\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n{step}"
    )
}

fn workflow_messages(text: &str) -> Vec<String> {
    check_workflow("ci.yml", text, &[])
        .into_iter()
        .map(|v| v.to_string())
        .collect()
}

fn assert_workflow_passes(text: &str) {
    let found = workflow_messages(text);
    assert!(found.is_empty(), "{found:#?}\n--- workflow\n{text}");
}

fn assert_workflow_rejected(text: &str, needle: &str) {
    let found = workflow_messages(text);
    assert!(
        found.iter().any(|m| m.contains(needle)),
        "want a violation containing {needle:?}, got {found:#?}\n--- workflow\n{text}"
    );
}

// Shapes from the issue: quoting and escaping.

#[test]
fn rejects_locked_flag_inside_a_quoted_argument() {
    assert_rejected("cargo test \"x --locked\"", "a quote");
    assert_rejected("cargo test 'x --locked'", "a quote");
    assert_rejected("cargo test \"--locked\"", "a quote");
}

#[test]
fn rejects_a_hash_inside_quotes_before_a_cargo_call() {
    assert_rejected("echo \"x #\"; cargo build", "a quote");
    assert_rejected("echo 'x #'; cargo build --locked", "a quote");
}

#[test]
fn rejects_an_escaped_redirect_operator() {
    assert_rejected("\\>& cargo build", "a backslash");
    assert_rejected("cargo build \\--locked", "a backslash");
}

// Line continuations.

#[test]
fn rejects_a_continuation_inside_the_cargo_word() {
    assert_rejected("car\\\ngo build", "a line continuation");
    assert_rejected("echo x && car\\\ngo build --locked", "a line continuation");
}

#[test]
fn rejects_a_continuation_after_the_cargo_word() {
    assert_rejected(
        "cargo test \\\n  --workspace \\\n  --locked",
        "a line continuation",
    );
    assert_rejected("cargo test --locked \\", "a line continuation");
}

// YAML key forms.

#[test]
fn rejects_a_double_quoted_run_key() {
    assert_workflow_rejected(
        &workflow("      - \"run\": cargo build\n"),
        "cargo build without --locked",
    );
}

#[test]
fn rejects_a_single_quoted_run_key() {
    assert_workflow_rejected(
        &workflow("      - 'run': cargo build\n"),
        "cargo build without --locked",
    );
}

#[test]
fn rejects_a_flow_mapping_run_step() {
    assert_workflow_rejected(
        &workflow("      - { run: cargo build }\n"),
        "cargo build without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - { name: x, \"run\": \"cargo build\" }\n"),
        "cargo build without --locked",
    );
}

// Substitutions.

#[test]
fn rejects_a_command_substitution_inside_a_quoted_argument() {
    assert_rejected("echo \"$(cargo build)\"", "a quote");
    assert_rejected("echo $(cargo build)", "a command substitution");
    assert_rejected("cargo build $(echo --locked)", "a command substitution");
}

#[test]
fn rejects_a_backtick_inside_a_quoted_argument() {
    assert_rejected("echo \"`cargo build`\"", "a quote");
    assert_rejected("echo `cargo build`", "a command substitution");
}

#[test]
fn rejects_a_process_substitution_inside_a_quoted_argument() {
    assert_rejected("diff \"<(cargo build)\" x", "a quote");
    assert_rejected("diff <(cargo build) x", "a process substitution");
    assert_rejected("cargo build --locked >(cat)", "a process substitution");
}

#[test]
fn rejects_a_substitution_inside_a_redirect_target() {
    assert_rejected("echo x >\"$(cargo build)\"", "a redirect");
    assert_rejected("echo x 2>$(cargo build)", "a redirect");
    assert_rejected("echo x >`cargo build`", "a redirect");
}

#[test]
fn rejects_a_parameter_expansion_on_a_cargo_line() {
    assert_rejected("cargo test $X --locked", "a parameter expansion");
    assert_rejected("cargo test ${y:---} --locked", "a parameter expansion");
    assert_rejected("echo $CARGO_HOME ~/.cargo/bin", "a parameter expansion");
}

#[test]
fn rejects_a_github_expression_on_any_line() {
    assert_rejected("${{ matrix.cmd }}", "a GitHub expression");
    assert_rejected("echo ${{ github.sha }}", "a GitHub expression");
}

// Redirects.

#[test]
fn accepts_a_trailing_stderr_to_stdout_duplication() {
    assert_passes("cargo test --locked 2>&1");
    assert_passes("cargo test --locked 2>&1 | tee log");
    assert_passes("cargo test --locked | tee log && echo done");
    assert_passes("cargo test --locked 2>&1|tee test.log");
}

#[test]
fn rejects_an_fd_close() {
    assert_rejected("cargo build --locked >&-", "a redirect");
    assert_rejected("cargo build --locked 2>&-", "a redirect");
}

#[test]
fn rejects_a_file_redirect_glued_to_the_flag() {
    assert_rejected("cargo build >&1---locked", "a redirect");
    assert_rejected("cargo build --locked2>&1", "a redirect");
    assert_rejected("cargo build --locked 2>&1---locked", "a redirect");
    assert_rejected("cargo build --locked 2>&12", "a redirect");
}

#[test]
fn rejects_every_other_redirect() {
    for line in [
        "cargo build --locked >log",
        "cargo build --locked 2>log",
        "cargo build --locked >>log",
        "cargo build --locked &>log",
        "cargo build --locked 1>&2",
        "cargo build --locked <in",
        "cargo build --locked <<<x",
        "cargo build --locked |& tee log",
    ] {
        assert_rejected(line, "a redirect");
    }
}

#[test]
fn rejects_a_stderr_duplication_that_does_not_end_the_command() {
    assert_rejected("cargo test 2>&1 --locked", "2>&1 must end its command");
}

#[test]
fn rejects_a_pipe_into_anything_but_tee_with_one_file() {
    assert_rejected("cargo build --locked | grep x", "a pipe");
    assert_rejected("cargo build --locked | tee -a log", "a pipe");
    assert_rejected("cargo build --locked | tee", "a pipe");
    assert_rejected("echo build | xargs cargo --locked", "a pipe");
}

// Names of cargo that a word scan would miss.

#[test]
fn rejects_a_cargo_word_split_by_quotes_or_expansions() {
    assert_rejected("c\"ar\"go build", "a quote");
    assert_rejected("ca''rgo build", "a quote");
    assert_rejected("car${x}go build", "a parameter expansion");
    assert_rejected("car$(true)go build", "a command substitution");
    assert_rejected("car`true`go build", "a command substitution");
    assert_rejected("car{,}go build", "the character '{'");
}

#[test]
fn rejects_a_word_that_names_cargo_but_is_not_a_cargo_call() {
    assert_rejected("x=cargo; echo", "names cargo but is not a cargo call");
    assert_rejected("ls ~/.cargo/bin", "names cargo but is not a cargo call");
    assert_rejected("echo cargo-deny", "names cargo but is not a cargo call");
    assert_rejected("cargo test --locked | tee cargo.log", "names cargo");
}

#[test]
fn checks_cargo_behind_a_wrapper_command() {
    assert_rejected("env cargo build", "cargo build without --locked");
    assert_rejected("command cargo build", "not in a command position");
    assert_rejected("echo cargo", "not in a command position");
    assert_passes("env cargo build --locked");
    assert_passes("time cargo build --locked");
}

#[test]
fn checks_a_cargo_path_and_any_letter_case() {
    assert_rejected("~/.cargo/bin/cargo build", "cargo build without --locked");
    assert_passes("~/.cargo/bin/cargo build --locked");
    assert_rejected("CARGO build", "cargo build without --locked");
}

// The rules of the cargo command line.

#[test]
fn every_subcommand_that_resolves_the_lockfile_needs_locked() {
    for sub in [
        "build", "b", "test", "t", "clippy", "run", "r", "doc", "d", "bench", "check", "c",
        "install", "nextest", "llvm-cov", "deny",
    ] {
        assert_rejected(
            &format!("cargo {sub} --workspace"),
            &format!("cargo {sub} without --locked"),
        );
        assert_passes(&format!("cargo {sub} --workspace --locked"));
    }
    assert_rejected("cargo nextest run --workspace", "without --locked");
    assert_passes("cargo llvm-cov --workspace --summary-only --locked");
}

#[test]
fn an_unclassified_subcommand_fails() {
    assert_rejected(
        "cargo frobnicate --locked",
        "unknown cargo subcommand \"frobnicate\"",
    );
    assert_rejected("cargo xtask dist", "unknown cargo subcommand \"xtask\"");
    assert_rejected(
        "cargo testing --locked",
        "unknown cargo subcommand \"testing\"",
    );
}

#[test]
fn cargo_without_a_subcommand_fails_unless_informational() {
    assert_rejected("cargo", "cargo without a visible subcommand");
    assert_rejected("cargo --locked", "cargo without a visible subcommand");
    assert_passes("cargo --version && cargo -V");
    assert_passes("cargo --list");
}

#[test]
fn global_options_toolchain_and_lock_position() {
    assert_passes("cargo --locked test");
    assert_rejected("cargo +1.99.0 test -p x", "cargo test without --locked");
    assert_passes("cargo +1.99.0 test -p x --locked");
    assert_rejected(
        "cargo --manifest-path bench/verify-ipc/Cargo.toml run --release",
        "cargo run without --locked",
    );
    assert_passes("cargo --manifest-path bench/verify-ipc/Cargo.toml run --release --locked");
    assert_rejected(
        "cargo --manifest-path --locked build",
        "cargo build without --locked",
    );
}

#[test]
fn a_toolchain_override_counts_only_as_the_first_argument() {
    // rustup reads `+toolchain` only there, so cargo takes a later one as its subcommand.
    assert_rejected(
        "cargo --version +1.99.0",
        "unknown cargo subcommand \"+1.99.0\"",
    );
    assert_rejected(
        "cargo --locked +1.99.0 build",
        "unknown cargo subcommand \"+1.99.0\"",
    );
    assert_passes("cargo +1.99.0 --version");
}

#[test]
fn locked_must_come_before_double_dash() {
    assert_rejected("cargo test -- --locked", "cargo test without --locked");
    assert_rejected("cargo run --locked -- cargo", "not in a command position");
    assert_passes("cargo run --locked -- --nocapture");
}

#[test]
fn each_command_of_a_line_is_checked() {
    assert_rejected("cd x && cargo test", "cargo test without --locked");
    assert_rejected(
        "cargo build --locked && cargo test",
        "cargo test without --locked",
    );
    assert_rejected(
        "cargo test & cargo build --locked",
        "cargo test without --locked",
    );
    assert_rejected(
        "cargo test | tee log && cargo build --locked",
        "cargo test without --locked",
    );
    assert_rejected(
        "cargo build --locked;cargo test",
        "cargo test without --locked",
    );
    assert_passes("cargo build --locked&&cargo test --locked || echo failed");
}

#[test]
fn comments_drop_the_rest_of_the_line() {
    assert_rejected("cargo test # --locked", "cargo test without --locked");
    assert_rejected("cargo test;# --locked", "cargo test without --locked");
    assert_rejected("cargo test x#--locked", "cargo test without --locked");
    assert_passes("# cargo test");
    assert_passes("cargo test --locked # the workspace");
}

#[test]
fn a_quote_in_a_comment_on_a_cargo_line_is_still_rejected() {
    // The comment can close a quote that an earlier line opened.
    assert_rejected("# x\" ; cargo build", "a quote");
    assert_rejected("# do not run cargo here, it's slow", "a quote");
}

#[test]
fn lines_that_do_not_name_cargo_are_not_checked() {
    assert_passes(
        "for user in other chain api; do\n  upper=$(echo \"$user\" | tr '[:lower:]' '[:upper:]')\n  echo \"ETHSWARM_${upper}_UID=$(id -u \"ethswarm-$user\")\" >> \"$GITHUB_ENV\"\ndone",
    );
    assert_passes("rustup toolchain install && rustc --version 2>/dev/null");
    assert_passes("bash scripts/check-workflows.sh \\\n  --flag");
}

#[test]
fn nolock_subcommands_and_arguments() {
    assert_passes("cargo fmt --all -- --check");
    assert_passes("cargo help build");
    assert_passes("cargo install cargo-fuzz --version 0.13.2 --locked");
    assert_passes("CARGO_INCREMENTAL=0 cargo build --locked");
    assert_rejected(
        "CARGO=cargo cargo build --locked",
        "names cargo but is not a cargo call",
    );
    assert_rejected("cargo fmt && cargo build", "cargo build without --locked");
}

#[test]
fn characters_outside_the_plain_set_are_rejected() {
    assert_rejected("cargo build --locked *", "the character '*'");
    assert_rejected("(cargo build --locked)", "the character '('");
    assert_rejected("! cargo build --locked", "the character '!'");
    assert_rejected("cargo build --locked\r", "the character '\\r'");
}

#[test]
fn findings_carry_the_line_of_their_command() {
    let found = check_run("echo a\n\ncargo build\necho b \\\n  && cargo test", &[]);
    let lines: Vec<usize> = found.iter().map(|f| f.line).collect();
    assert_eq!(lines, vec![2, 3], "{found:#?}");
}

// The allow-list.

#[test]
fn an_allow_list_entry_passes_exactly_its_line() {
    let allow = [Allow {
        file: "ci.yml",
        kind: AllowKind::Run,
        line: "cargo build \"--locked\"",
        reason: "test",
    }];
    assert!(check_run("  cargo build \"--locked\"  ", &allow).is_empty());
    assert!(!check_run("cargo build \"--locked\" ", &[]).is_empty());
    assert!(!check_run("cargo build \"--locked\"x", &allow).is_empty());
    assert!(!check_run("cargo test \"--locked\"", &allow).is_empty());
}

#[test]
fn every_reviewed_allow_entry_has_a_reason_and_is_needed() {
    for entry in ALLOW {
        assert!(!entry.reason.trim().is_empty(), "{entry:?} has no reason");
        assert!(
            !check_run(entry.line, &[]).is_empty(),
            "{entry:?} passes without the entry, so remove it"
        );
    }
}

// The YAML layer.

#[test]
fn checks_inline_and_literal_block_run_values() {
    assert_workflow_rejected(
        &workflow("      - run: cargo test -p y\n"),
        "ERROR ci.yml:8: cargo test without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - run: |\n          echo x\n          cargo test\n"),
        "ERROR ci.yml:10: cargo test without --locked: cargo test",
    );
    assert_workflow_rejected(
        &workflow("      - run: |\n\n          echo x\n\n          cargo test\n"),
        "ERROR ci.yml:12: cargo test without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - run: |-\n          cargo test\n      - run: |+\n          echo\n          cargo b\n"),
        "ERROR ci.yml:12: cargo b without --locked",
    );
    assert_workflow_passes(&workflow(
        "      - run: |\n          cargo build --locked\n          cargo test --locked\n",
    ));
    assert_workflow_passes(&workflow("      - run: cargo fmt --all -- --check\n"));
}

#[test]
fn checks_the_decoded_value_of_every_scalar_style() {
    assert_workflow_rejected(
        &workflow("      - run: \"cargo build --locked\\ncargo test\"\n"),
        "cargo test without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - run: 'cargo test'\n"),
        "cargo test without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - run: cargo test\n          -p x\n"),
        "cargo test without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - run: cargo build # --locked\n"),
        "cargo build without --locked",
    );
    assert_workflow_passes(&workflow("      - run: cargo test\n          --locked\n"));
}

#[test]
fn a_folded_run_value_that_can_run_cargo_is_refused() {
    for header in [">", ">-", ">2"] {
        assert_workflow_rejected(
            &workflow(&format!(
                "      - run: {header}\n          cargo build --locked\n      - run: echo next\n"
            )),
            "folded run: scalar can run cargo",
        );
    }
    assert_workflow_passes(&workflow(
        "      - run: >\n          echo one\n          echo two\n",
    ));
}

#[test]
fn run_keys_through_aliases_and_in_any_letter_case() {
    assert_workflow_rejected(
        &workflow("      - name: &cmd cargo build\n        run: *cmd\n"),
        "cargo build without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - name: &key run\n        x: y\n      - *key : cargo build\n"),
        "cargo build without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - Run: cargo build\n"),
        "cargo build without --locked",
    );
}

#[test]
fn run_keys_anywhere_in_the_tree_are_checked() {
    assert_workflow_rejected(
        &workflow("      - uses: ./x\n        with:\n          run: cargo build\n"),
        "cargo build without --locked",
    );
    assert_workflow_passes(&format!(
        "defaults:\n  run:\n    shell: bash\n{}",
        workflow("      - run: echo ok\n")
    ));
}

#[test]
fn values_of_other_keys_are_not_run_values() {
    assert_workflow_passes(&workflow(
        "      - name: cargo build\n        uses: ./x\n        with:\n          tool: cargo-deny@0.20.2\n",
    ));
}

#[test]
fn every_document_is_checked() {
    assert_workflow_rejected(
        &format!(
            "{}---\n{}",
            workflow("      - run: echo ok\n"),
            workflow("      - run: cargo test\n")
        ),
        "cargo test without --locked",
    );
}

#[test]
fn invalid_yaml_fails() {
    assert_workflow_rejected("jobs: [\n", "not valid YAML");
}

// Review cycle 1.

#[test]
fn run_passes_the_words_after_its_first_positional_argument_to_the_binary() {
    let after = |sub: &str| format!("cargo {sub} has --locked only after a positional argument");
    assert_rejected("cargo run x --locked", &after("run"));
    assert_rejected("cargo r --bin p y --locked", &after("r"));
    assert_rejected("cargo run -q x --locked", &after("run"));
    assert_rejected("cargo run --release x --locked", &after("run"));
    assert_passes("cargo run --locked x");
    assert_passes("cargo run --bin p --locked -- x");
    assert_passes("cargo r -p x --release --locked");
    assert_passes("cargo run --bin --locked");
    assert_passes("cargo --locked run x");
    assert_passes("cargo test x --locked");
}

#[test]
fn rejects_a_cargo_alias_variable() {
    assert_rejected("CARGO_ALIAS_FMT=build cargo fmt", "CARGO_ALIAS_");
    assert_rejected("export CARGO_ALIAS_FMT=build", "CARGO_ALIAS_");
    assert_rejected(
        "env CARGO_ALIAS_CLIPPY=build cargo clippy --locked",
        "CARGO_ALIAS_",
    );
    assert_rejected("export cargo_alias_fmt", "CARGO_ALIAS_");
    assert_passes("cargo build --locked CARGO_ALIAS_X=y");
}

#[test]
fn rejects_a_cargo_alias_key_in_any_env_block() {
    let wf = |env_at: &str| match env_at {
        "workflow" => format!(
            "env:\n  CARGO_ALIAS_FMT: build\n{}",
            workflow("      - run: cargo fmt\n")
        ),
        "job" => workflow("      - run: cargo fmt\n").replace(
            "    runs-on:",
            "    env:\n      CARGO_ALIAS_FMT: build\n    runs-on:",
        ),
        _ => workflow("      - run: cargo fmt\n        env:\n          cargo_alias_fmt: build\n"),
    };
    for at in ["workflow", "job", "step"] {
        assert_workflow_rejected(&wf(at), "CARGO_ALIAS_");
    }
}

#[test]
fn rejects_a_config_option_that_can_define_an_alias() {
    assert_rejected("cargo --config ci/alias.toml fmt", "--config");
    assert_rejected("cargo --config alias.fmt=build fmt", "--config");
    assert_rejected("cargo --config=alias.fmt=build fmt", "--config");
    assert_rejected("cargo --config=ci/x.toml build --locked", "--config");
    // Cargo reads `a=1` as a file if one has that name, so no value is safe before the
    // subcommand. After it, `--config` cannot change which subcommand runs.
    assert_rejected("cargo --config a=1 fmt --all", "--config");
    assert_rejected("cargo --config net.offline=true build --locked", "--config");
    assert_passes("cargo build --locked --config net.offline=true");
    assert_passes("cargo fmt --config x=1");
}

#[test]
fn rejects_a_short_option_cluster_with_c_or_z() {
    assert_rejected("cargo -qC fmt build", "short-option cluster");
    assert_rejected("cargo -vZ x fmt", "short-option cluster");
    assert_rejected("cargo -Zunstable-options fmt", "short-option cluster");
    assert_rejected("cargo -C fmt build", "cargo build without --locked");
    assert_passes("cargo -C fmt build --locked");
    assert_passes("cargo -vq build --locked");
}

#[test]
fn rejects_brace_sequences_globs_nul_and_ansi_c_quotes() {
    assert_rejected("car{g..g}o build", "the character '{'");
    assert_rejected("c{a,x}rgo build", "the character '{'");
    assert_rejected("~/.carg?/bin/carg? build", "the character '?'");
    assert_rejected("[c]argo build", "the character '['");
    assert_rejected("ca* build", "the character '*'");
    assert_rejected("./bin/* build", "the character '*'");
    assert_rejected("echo \0 x", "the character '\\0'");
    assert_rejected("$'\\x63argo' build", "a parameter expansion");
    assert_passes("ls ? [ab] {x}");
    assert_passes("upper=$(echo \"$user\" | tr '[:lower:]' '[:upper:]')");
}

#[test]
fn shell_values_are_checked_as_commands() {
    assert_workflow_rejected(
        &workflow("      - shell: cargo run --bin x -- {0}\n        run: echo hi\n"),
        "cargo run without --locked",
    );
    assert_workflow_rejected(
        &workflow("      - shell: bash -c \"cargo build && bash {0}\"\n        run: echo hi\n"),
        "a quote",
    );
    assert_workflow_rejected(
        &format!(
            "defaults:\n  run:\n    shell: cargo run -- {{0}}\n{}",
            workflow("      - run: echo hi\n")
        ),
        "cargo run without --locked",
    );
    assert_workflow_passes(&workflow("      - shell: perl {0}\n        run: print 1\n"));
}

#[test]
fn a_step_that_can_run_cargo_needs_a_bash_or_sh_shell() {
    for shell in [
        "perl {0}",
        "python",
        "pwsh",
        "bash -c {0}",
        "bash {0} x",
        "zsh {0}",
    ] {
        assert_workflow_rejected(
            &workflow(&format!(
                "      - shell: {shell}\n        run: cargo build --locked\n"
            )),
            "shell",
        );
    }
    for shell in [
        "bash",
        "sh",
        "bash {0}",
        "sh -e {0}",
        "bash --noprofile --norc -eo pipefail {0}",
        "bash -euo pipefail {0}",
    ] {
        assert_workflow_passes(&workflow(&format!(
            "      - shell: {shell}\n        run: cargo build --locked\n"
        )));
    }
}

#[test]
fn the_default_shell_comes_from_the_job_then_the_workflow() {
    let step = "      - run: cargo build --locked\n";
    let workflow_pwsh = format!("defaults:\n  run:\n    shell: pwsh\n{}", workflow(step));
    assert_workflow_rejected(&workflow_pwsh, "shell");
    let job_pwsh = workflow(step).replace(
        "    runs-on:",
        "    defaults:\n      run:\n        shell: pwsh\n    runs-on:",
    );
    assert_workflow_rejected(&job_pwsh, "shell");
    let job_bash = workflow_pwsh.replace(
        "    runs-on:",
        "    defaults:\n      run:\n        shell: bash\n    runs-on:",
    );
    assert_workflow_passes(&job_bash);
    let step_bash = workflow_pwsh.replace(
        step,
        "      - run: cargo build --locked\n        shell: bash\n",
    );
    assert_workflow_passes(&step_bash);
}

#[test]
fn a_runner_without_a_known_bash_default_needs_an_explicit_shell() {
    let step = "      - run: cargo build --locked\n";
    for runs_on in [
        "windows-latest",
        "${{ matrix.os }}",
        "[self-hosted, x64]",
        "{ group: big }",
    ] {
        let wf = workflow(step).replace("runs-on: ubuntu-24.04", &format!("runs-on: {runs_on}"));
        assert_workflow_rejected(&wf, "shell");
        let explicit = wf.replace(
            step,
            "      - run: cargo build --locked\n        shell: bash\n",
        );
        assert_workflow_passes(&explicit);
    }
    for runs_on in ["macos-15", "[self-hosted, linux, x64]"] {
        let wf = workflow(step).replace("runs-on: ubuntu-24.04", &format!("runs-on: {runs_on}"));
        assert_workflow_passes(&wf);
    }
}

#[test]
fn composite_action_steps_are_checked() {
    let action = |steps: &str| format!("name: a\nruns:\n  using: composite\n  steps:\n{steps}");
    assert_workflow_rejected(
        &action("    - run: cargo build\n      shell: bash\n"),
        "cargo build without --locked",
    );
    assert_workflow_rejected(&action("    - run: cargo build --locked\n"), "shell");
    assert_workflow_passes(&action(
        "    - run: cargo build --locked\n      shell: bash\n",
    ));
}

#[test]
fn actions_that_run_cargo_need_an_allow_entry() {
    let step = "      - uses: actions-rs/cargo@844f36862e911db73fe0815f00a4a2602c279505\n        with:\n          command: build\n";
    assert_workflow_rejected(&workflow(step), "actions-rs/cargo");
    let allow = [Allow {
        file: "ci.yml",
        kind: AllowKind::Uses,
        line: "actions-rs/cargo@844f36862e911db73fe0815f00a4a2602c279505",
        reason: "test",
    }];
    assert!(check_workflow("ci.yml", &workflow(step), &allow).is_empty());
    // An entry for another file or of another kind does not match.
    for (file, kind) in [("other.yml", AllowKind::Uses), ("ci.yml", AllowKind::Run)] {
        let other = [Allow {
            file,
            kind,
            ..allow[0]
        }];
        assert!(!check_workflow("ci.yml", &workflow(step), &other).is_empty());
    }
    for with in ["args: cargo build", "entrypoint: cargo"] {
        assert_workflow_rejected(
            &workflow(&format!(
                "      - uses: docker://rust:1.99\n        with:\n          {with}\n"
            )),
            "docker://rust:1.99",
        );
    }
    assert_workflow_passes(&workflow(
        "      - uses: docker://alpine:3\n        with:\n          args: echo hi\n",
    ));
}

#[test]
fn rejects_unicode_line_breaks_and_a_late_byte_order_mark() {
    for bad in ["\u{0085}", "\u{2028}", "\u{2029}", "\u{feff}"] {
        assert_workflow_rejected(
            &workflow(&format!("      - run: echo x{bad}\n")),
            "line break or byte order mark",
        );
    }
    assert_workflow_passes(&format!("\u{feff}{}", workflow("      - run: echo ok\n")));
}

#[test]
fn cargo_config_aliases_of_classified_names_fail() {
    let msgs = |text: &str| -> Vec<String> {
        check_cargo_config(".cargo/config.toml", text)
            .into_iter()
            .map(|v| v.to_string())
            .collect()
    };
    for text in [
        "[alias]\nfmt = \"build\"\n",
        "[ alias ]\n\"clippy\" = [\"run\", \"x\"]\n",
        "alias.fmt = \"build\"\n",
        "[build]\njobs = 2\n[alias]\n# x\ndeny = \"b\"\n",
        "alias = { fmt = \"b\" }\n",
        "[\"alias\"]\nfmt = \"b\"\n",
        // Shapes that a line reader gets wrong.
        "[alias]\n\"\\u0063lippy\" = \"run -q --\"\n",
        "[alias] # see [docs]\nclippy = \"run -p x --\"\n",
        "x = \"\"\"\n[foo]\n\"\"\"\nalias.fmt = \"b\"\n",
        // An include can bring in any alias, and a file that does not parse is unknown.
        "include = [\"aliases.toml\"]\n",
        "[alias\nfmt = \"b\"\n",
        "alias = \"fmt\"\n",
    ] {
        assert!(!msgs(text).is_empty(), "{text:?} passes");
    }
    for text in [
        "[alias]\nmy-build = \"build --locked\"\n",
        "# [alias]\n# fmt = \"b\"\n[build]\njobs = 2\n",
        "[net]\noffline = true\n",
        "x = \"\"\"\n[alias]\nfmt = 1\n\"\"\"\n",
    ] {
        assert!(msgs(text).is_empty(), "{text:?}: {:?}", msgs(text));
    }
}

// Scans of paths and of a repository.

fn write(path: &std::path::Path, text: &str) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, text).expect("write");
}

fn git(root: &std::path::Path, args: &[&str]) {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn check_repo_reads_workflows_actions_and_cargo_configs() {
    let repo = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    write(
        &root.join(".github/workflows/ci.yml"),
        &workflow("      - run: cargo fmt\n"),
    );
    write(
        &root.join(".github/actions/a/b/action.yml"),
        "runs:\n  using: composite\n  steps:\n    - run: cargo test\n      shell: bash\n",
    );
    write(
        &root.join(".cargo/config.toml"),
        "[alias]\nclippy = \"run x\"\n",
    );
    write(&root.join("sub/.cargo/config"), "[net]\noffline = true\n");
    // Without git, nothing is skipped: a CACHEDIR.TAG or a .git file can be committed.
    write(&root.join("target/CACHEDIR.TAG"), "x");
    write(
        &root.join("target/.cargo/config.toml"),
        "alias.fmt = \"b\"\n",
    );
    write(&root.join("nested/.git"), "gitdir: x\n");
    write(
        &root.join("nested/.cargo/config.toml"),
        "alias.fmt = \"b\"\n",
    );

    let scan = check_repo(root, &[]).expect("scan");
    assert_eq!((scan.workflow_files, scan.config_files), (2, 4));
    let found: Vec<String> = scan.violations.iter().map(|v| v.to_string()).collect();
    assert_eq!(found.len(), 4, "{found:#?}");
    assert!(
        found[0].contains("a/b/action.yml:4: cargo test without --locked"),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("nested/.cargo/config.toml")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("target/.cargo/config.toml")),
        "{found:#?}"
    );
}

#[cfg(unix)]
#[test]
fn check_repo_in_git_reads_tracked_and_untracked_configs_and_follows_cargo_links() {
    let repo = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    git(root, &["init", "-q"]);
    write(
        &root.join(".github/workflows/ci.yml"),
        &workflow("      - run: cargo fmt\n"),
    );
    write(&root.join("target/CACHEDIR.TAG"), "x");
    write(
        &root.join("target/.cargo/config.toml"),
        "alias.fmt = \"b\"\n",
    );
    write(&root.join("ci/cargo/config.toml"), "alias.clippy = \"b\"\n");
    std::os::unix::fs::symlink("ci/cargo", root.join(".cargo")).expect("symlink");
    // A committed CACHEDIR.TAG does not hide a committed config.
    write(&root.join("cache/CACHEDIR.TAG"), "x");
    write(&root.join("cache/.cargo/config"), "alias.deny = \"b\"\n");
    git(root, &["add", ".github", "ci", ".cargo", "cache"]);
    let scan = check_repo(root, &[]).expect("scan");
    let found: Vec<String> = scan.violations.iter().map(|v| v.to_string()).collect();
    assert!(
        found.iter().any(|f| f.contains("alias \"clippy\"")),
        "{found:#?}"
    );
    assert!(
        found.iter().any(|f| f.contains("alias \"deny\"")),
        "{found:#?}"
    );
    // Cargo reads an untracked config too, also one that git ignores.
    assert!(
        found
            .iter()
            .any(|f| f.contains("target/.cargo/config.toml: alias \"fmt\"")),
        "{found:#?}"
    );
    write(&root.join(".gitignore"), "target/\n");
    write(&root.join("sub/.cargo/config"), "alias.test = \"b\"\n");
    git(root, &["add", ".gitignore"]);
    let scan = check_repo(root, &[]).expect("scan");
    let found: Vec<String> = scan.violations.iter().map(|v| v.to_string()).collect();
    assert_eq!(scan.config_files, 4, "{found:#?}");
    assert!(
        found
            .iter()
            .any(|f| f.contains("target/.cargo/config.toml")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("sub/.cargo/config: alias \"test\"")),
        "{found:#?}"
    );

    // A tracked .cargo link out of the repository fails.
    let outside = tempfile::TempDir::new().expect("tempdir");
    write(
        &outside.path().join("config.toml"),
        "[net]\noffline = true\n",
    );
    std::fs::remove_file(root.join(".cargo")).expect("rm");
    std::os::unix::fs::symlink(outside.path(), root.join(".cargo")).expect("symlink");
    git(root, &["add", ".cargo"]);
    let scan = check_repo(root, &[]).expect("scan");
    let found: Vec<String> = scan.violations.iter().map(|v| v.to_string()).collect();
    assert!(
        found.iter().any(|f| f.contains("outside the repository")),
        "{found:#?}"
    );

    // An untracked .cargo link out of the repository fails too.
    std::fs::remove_file(root.join(".cargo")).expect("rm");
    git(root, &["rm", "-q", "--cached", ".cargo"]);
    std::fs::create_dir_all(root.join("u")).expect("mkdir");
    std::os::unix::fs::symlink(outside.path(), root.join("u/.cargo")).expect("symlink");
    let scan = check_repo(root, &[]).expect("scan");
    let found: Vec<String> = scan.violations.iter().map(|v| v.to_string()).collect();
    assert!(
        found
            .iter()
            .any(|f| f.contains("u/.cargo") && f.contains("outside the repository")),
        "{found:#?}"
    );
}

#[cfg(unix)]
#[test]
fn local_actions_are_followed_in_repo_mode() {
    let repo = tempfile::TempDir::new().expect("tempdir");
    let root = repo.path();
    let wf = |uses: &str| workflow(&format!("      - uses: {uses}\n"));
    let composite = |step: &str| {
        format!("runs:\n  using: composite\n  steps:\n    - {step}\n      shell: bash\n")
    };
    write(&root.join(".github/workflows/ci.yml"), &wf("./ci/build"));
    write(
        &root.join("ci/build/action.yml"),
        &composite("uses: ./ci/inner"),
    );
    write(
        &root.join("ci/inner/action.yaml"),
        &composite("run: cargo build"),
    );
    let found: Vec<String> = check_repo(root, &[])
        .expect("scan")
        .violations
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert!(
        found
            .iter()
            .any(|f| f.contains("ci/inner/action.yaml:4: cargo build without --locked")),
        "{found:#?}"
    );

    // `uses: ./` is the action at the root, and a job-level local workflow is read too.
    write(&root.join(".github/workflows/ci.yml"), &wf("./"));
    write(&root.join("action.yml"), &composite("run: cargo test"));
    write(
        &root.join(".github/workflows/call.yml"),
        "on: push\njobs:\n  c:\n    uses: ./ci/called.yml\n",
    );
    write(
        &root.join("ci/called.yml"),
        &workflow("      - run: cargo check\n"),
    );
    let found: Vec<String> = check_repo(root, &[])
        .expect("scan")
        .violations
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert!(
        found
            .iter()
            .any(|f| f.contains("action.yml:4: cargo test without")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("cargo check without --locked")),
        "{found:#?}"
    );

    // A missing action, and a link out of the repository, fail.
    write(&root.join(".github/workflows/ci.yml"), &wf("./ci/absent"));
    let outside = tempfile::TempDir::new().expect("tempdir");
    write(&outside.path().join("action.yml"), &composite("run: echo"));
    std::os::unix::fs::symlink(outside.path(), root.join("ci/out")).expect("symlink");
    write(&root.join(".github/workflows/out.yml"), &wf("./ci/out"));
    let found: Vec<String> = check_repo(root, &[])
        .expect("scan")
        .violations
        .iter()
        .map(|v| v.to_string())
        .collect();
    assert!(
        found
            .iter()
            .any(|f| f.contains("./ci/absent") && f.contains("no action.yml")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|f| f.contains("./ci/out") && f.contains("outside the repository")),
        "{found:#?}"
    );
}

#[test]
fn check_paths_fails_closed_on_nothing_to_read() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let missing = dir.path().join("absent");
    let err = check_paths(std::slice::from_ref(&missing), &[]).expect_err("missing");
    assert!(matches!(err, PathError::Nothing(_)));
    assert!(err
        .to_string()
        .contains("absent: no such file or directory"));
    let err = check_paths(&[dir.path().to_path_buf()], &[]).expect_err("empty");
    assert!(err.to_string().contains("no workflow files in"));
    assert!(matches!(
        check_repo(dir.path(), &[]),
        Err(PathError::Nothing(_))
    ));
}

#[cfg(unix)]
#[test]
fn check_paths_reports_an_unreadable_file() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let file = dir.path().join("ci.yml");
    write(&file, "on: push\n");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("chmod");
    if std::fs::read(&file).is_ok() {
        return; // root reads any file
    }
    let err = check_paths(&[dir.path().to_path_buf()], &[]).expect_err("unreadable");
    assert!(matches!(err, PathError::Unreadable(_)), "{err}");
}

// Review cycle 2.

#[test]
fn llvm_cov_run_gives_the_words_after_its_first_positional_argument_to_the_binary() {
    let after = |sub: &str| format!("cargo {sub} has --locked only after a positional argument");
    assert_rejected("cargo llvm-cov run x --locked", &after("llvm-cov"));
    assert_rejected("cargo llvm-cov x --locked", &after("llvm-cov"));
    assert_rejected("cargo nextest run x --locked", &after("nextest"));
    assert_passes("cargo llvm-cov run --locked x");
    assert_passes("cargo llvm-cov --locked run x");
    assert_passes("cargo llvm-cov test --workspace --locked");
    assert_passes("cargo llvm-cov --workspace --summary-only --locked");
    assert_passes("cargo deny --locked check");
    assert_passes("cargo deny check --locked");
    assert_rejected("cargo deny check bans --locked", &after("deny"));
}

#[test]
fn an_expansion_that_can_be_a_command_word_can_run_cargo() {
    assert_rejected("${x:-car}go build", "a parameter expansion");
    assert_rejected("$(echo car)go build", "a command substitution");
    assert_rejected("x=car; y=go; $x$y build", "a parameter expansion");
    assert_rejected("c=car\n${c}go build", "a parameter expansion");
    assert_rejected("echo x; $c build", "a parameter expansion");
    assert_rejected("env $c build", "a parameter expansion");
    assert_rejected("X=1 $c build", "a parameter expansion");
    assert_rejected("x=\"1 2\" $c build", "a quote");
    assert_rejected("echo $(${c}go build)", "a command substitution");
    // An expansion that is only an argument is not checked.
    assert_passes("echo \"ETHSWARM_${upper}_UID=$(id -u \"ethswarm-$user\")\" >> \"$GITHUB_ENV\"");
    assert_passes("echo $HOME/x");
}

#[test]
fn rejects_a_cargo_word_that_is_not_a_command_word() {
    assert_rejected("xargs -a f -I fmt cargo fmt", "not in a command position");
    assert_rejected(
        "xargs -a f -I --version cargo --version",
        "not in a command position",
    );
    assert_rejected(
        "ln -sf /home/runner/.rustup/toolchains/1.99.0-x86_64-unknown-linux-gnu/bin/cargo fmt",
        "not in a command position",
    );
    assert_rejected("echo cargo", "not in a command position");
    assert_rejected("env -i cargo build --locked", "not in a command position");
    assert_rejected("cargo run --locked -- cargo", "not in a command position");
    assert_passes("env cargo build --locked");
    assert_passes("env CARGO_INCREMENTAL=0 cargo build --locked");
    assert_passes("time cargo build --locked");
    assert_passes("nice cargo build --locked");
    assert_passes("sudo cargo build --locked");
    assert_passes("if cargo build --locked; then echo ok; fi");
    assert_passes("X=1 cargo build --locked && cargo test --locked");
}

#[test]
fn rejects_a_variable_that_moves_cargo_config() {
    assert_rejected("CARGO_HOME=ci/home cargo fmt --check", "CARGO_HOME");
    assert_rejected("export CARGO_HOME=ci/home", "CARGO_HOME");
    assert_rejected("HOME=/tmp/h cargo fmt", "HOME");
    assert_rejected("cargo --config include=ci/a.toml fmt", "--config");
    let wf = format!(
        "env:\n  CARGO_HOME: ci/home\n{}",
        workflow("      - run: cargo clippy --locked\n")
    );
    assert_workflow_rejected(&wf, "CARGO_HOME");
    let step = workflow("      - run: cargo fmt\n        env:\n          home: /x\n");
    assert_workflow_rejected(&step, "HOME");
    // A `home` input of an action is not an environment variable.
    assert_workflow_passes(&workflow(
        "      - uses: ./x\n        with:\n          home: /x\n",
    ));
}

#[test]
fn a_docker_action_that_can_run_cargo_fails() {
    for runs in [
        "  using: docker\n  image: Dockerfile\n  entrypoint: cargo\n  args: [build]\n",
        "  using: docker\n  image: Dockerfile\n  args:\n    - cargo\n    - build\n",
        "  using: docker\n  image: Dockerfile\n  pre-entrypoint: cargo build\n",
        "  using: docker\n  image: Dockerfile\n  post-entrypoint: /usr/local/bin/cargo\n",
    ] {
        assert_workflow_rejected(&format!("name: a\nruns:\n{runs}"), "can run cargo");
    }
    assert_workflow_passes(
        "name: a\nruns:\n  using: docker\n  image: Dockerfile\n  args: [echo, hi]\n",
    );
}

#[test]
fn keys_that_differ_only_in_letter_case_fail() {
    assert_workflow_rejected(
        &workflow("      - Shell: bash\n        shell: pwsh\n        run: cargo build --locked\n"),
        "letter case",
    );
    assert_workflow_rejected(
        &workflow("      - run: cargo build --locked\n        shell: bash\n        shell: pwsh\n"),
        "",
    );
}

// Deliberate bypasses after the fail-closed rewrite.

#[test]
fn a_redirect_before_the_command_word_keeps_the_next_word_a_command_word() {
    for line in [
        "x=car; y=go; >/dev/null $x$y build",
        "> /dev/null $c build",
        "2>/dev/null $c build",
        "<in $c build",
        "X=1 >o $c build",
        "<<< x $c build",
        ">>log 2>&1 $c build",
    ] {
        assert_rejected(line, "a redirect");
    }
    // A quote or a backslash before `<` or `>` makes it part of the command word.
    assert_rejected("\"<\"/$c build", "a quote");
    assert_rejected("\\>/$c build", "a backslash");
    // A quoted name is not an assignment, so the word is the command word.
    assert_rejected("\"x\"=/$c build", "a quote");
    // A redirect after the command word is not checked.
    assert_passes("echo x >/dev/null $y");
}

#[test]
fn trap_coproc_find_parallel_script_and_ssh_run_their_arguments() {
    assert_rejected("trap \"$x$y build\" EXIT", "a quote");
    for line in [
        "coproc $c build",
        "find . -exec $c build",
        "parallel $c ::: build",
        "script -c $c",
        "ssh host $c build",
    ] {
        assert_rejected(line, "a parameter expansion");
    }
}

#[test]
fn an_anchored_mapping_cannot_move_the_cargo_config() {
    assert_workflow_rejected(
        &workflow(
            "      - uses: ./x\n        with: &w {HOME: /tmp/h}\n      - run: cargo fmt\n        env: *w\n",
        ),
        "HOME",
    );
    assert_workflow_rejected(
        &workflow(
            "      - uses: ./x\n        with: &w\n          cargo_home: /tmp/h\n      - run: cargo fmt\n        env:\n          <<: *w\n",
        ),
        "CARGO_HOME",
    );
    // Without an anchor, a `home` input of an action is not an environment variable.
    assert_workflow_passes(&workflow("      - uses: ./x\n        with: {home: /x}\n"));
}

#[test]
fn llvm_cov_options_take_the_next_word_as_their_value() {
    assert_passes("cargo llvm-cov --lcov --output-path lcov.info --locked");
    assert_passes("cargo llvm-cov report --lcov --output-path lcov.info --locked");
    assert_passes("cargo llvm-cov --workspace --fail-under-lines 90 --locked");
    assert_passes("cargo llvm-cov run --output-dir d --bin p --locked x");
    // cargo-llvm-cov takes the next word as the value, also if it starts with `-`.
    assert_rejected(
        "cargo llvm-cov run --features --locked x",
        "--locked only as the value of \"--features\"",
    );
    assert_rejected(
        "cargo llvm-cov -p --locked test",
        "--locked only as the value of \"-p\"",
    );
    assert_rejected("cargo llvm-cov run -vF --locked x", "short-option cluster");
    assert_rejected("cargo llvm-cov -qp x --locked", "short-option cluster");
    assert_passes("cargo llvm-cov -vq --locked");
}

#[test]
fn locked_after_a_positional_argument_is_named_as_such() {
    for (line, sub) in [
        ("cargo deny check bans --locked", "deny"),
        ("cargo run x --locked", "run"),
        ("cargo llvm-cov run x --locked", "llvm-cov"),
        ("cargo llvm-cov report x --locked", "llvm-cov"),
        ("cargo nextest run x --locked", "nextest"),
    ] {
        assert_rejected(
            line,
            &format!("cargo {sub} has --locked only after a positional argument"),
        );
    }
    assert_rejected("cargo run x", "cargo run without --locked");
    assert_rejected("cargo run -- --locked", "cargo run without --locked");
}

#[cfg(unix)]
#[test]
fn check_repo_walks_a_root_that_git_ignores_or_does_not_track() {
    let outer = tempfile::TempDir::new().expect("tempdir");
    git(outer.path(), &["init", "-q"]);
    write(&outer.path().join(".gitignore"), "ignored/\n");
    git(outer.path(), &["add", ".gitignore"]);
    for dir in ["ignored", "untracked"] {
        let root = outer.path().join(dir);
        write(
            &root.join(".github/workflows/ci.yml"),
            &workflow("      - run: cargo fmt\n"),
        );
        write(&root.join(".cargo/config.toml"), "alias.fmt = \"b\"\n");
        write(&root.join("a/.cargo/config"), "alias.clippy = \"b\"\n");
        let scan = check_repo(&root, &[]).expect("scan");
        let found: Vec<String> = scan.violations.iter().map(|v| v.to_string()).collect();
        assert_eq!(scan.config_files, 2, "{dir}: {found:#?}");
        assert!(
            found.iter().any(|f| f.contains("alias \"fmt\"")),
            "{dir}: {found:#?}"
        );
        assert!(
            found.iter().any(|f| f.contains("alias \"clippy\"")),
            "{dir}: {found:#?}"
        );
    }
}

// Review cycle 1.

#[test]
fn an_escaped_redirect_character_does_not_join_the_next_operator() {
    for line in [
        "x=car; y=go; echo a\\>|$x$y build",
        "x=car; y=go; echo a\\>&$x$y build",
        "x=car; y=go; echo a\\<|$x$y build",
        "echo \"a>\"|$c build",
    ] {
        assert_rejected(line, "");
    }
}

#[test]
fn find_xargs_and_parallel_run_their_arguments_up_to_the_unquoted_end_of_the_command() {
    assert_rejected(
        "x=car; y=go; find . -maxdepth 0 -exec true ';' -exec $x$y build ';'",
        "a quote",
    );
    assert_rejected("find . -exec true \\; -exec $c build \\;", "a backslash");
    assert_rejected(
        "x=car; y=go; echo b | xargs -I {} -P 1 $x$y {}",
        "the character '{'",
    );
    assert_rejected("parallel -q ';' x $c ::: build", "a quote");
    assert_rejected(
        "find . -exec $(echo; echo) $c build",
        "a command substitution",
    );
    // An unquoted operator ends the command.
    assert_passes("find . -name x -exec rm {} + && echo \"$x\"");
    assert_passes("ls | xargs -n 1 echo; echo \"$x\"");
}

#[test]
fn find_and_trap_count_only_the_words_that_they_can_run() {
    assert_passes("find \"$DIR\" -name x -delete");
    assert_passes("trap 'rm -rf \"$tmp\"' EXIT");
    assert_passes("trap \"rm -f ${tmp}\" EXIT");
    assert_passes("trap - EXIT");
    // An expansion in the arguments of find can be `-exec`, and an unquoted one can also hold
    // the command.
    assert_rejected("find \"$d\" $c build", "a quote");
    assert_rejected("find . $d build", "a parameter expansion");
    assert_rejected("find . -execdir $c build", "a parameter expansion");
    assert_rejected("find . -okdir $c build", "a parameter expansion");
    // The action of trap is a command line.
    assert_rejected("trap \"$x$y build\" EXIT", "a quote");
    assert_rejected("trap -- \"$c build\" EXIT", "a quote");
    assert_rejected("trap \"echo; $c build\" EXIT", "a quote");
    assert_rejected("trap 'echo \"$(date)\"; $c build' EXIT", "a quote");
    assert_rejected("trap $(echo x) EXIT", "a command substitution");
    // An expansion in the arguments of ssh can be an option such as `-oProxyCommand=..`, so
    // each one can run cargo (rule 3 of the module docs).
    assert_rejected("ssh \"$HOST\" uptime", "a quote");
    assert_passes("ssh host uptime");
}

#[test]
fn llvm_cov_reads_m_cargo_profile_and_archive_file_with_a_value() {
    assert_passes("cargo llvm-cov -m m/Cargo.toml --locked");
    assert_passes("cargo llvm-cov nextest --cargo-profile ci --locked");
    assert_passes("cargo llvm-cov nextest --archive-file a.tar.zst --locked");
    assert_rejected(
        "cargo llvm-cov -m --locked test",
        "--locked only as the value of \"-m\"",
    );
    assert_rejected(
        "cargo llvm-cov nextest --cargo-profile --locked",
        "--locked only as the value of \"--cargo-profile\"",
    );
    assert_rejected("cargo llvm-cov -vm --locked", "short-option cluster");
}

#[test]
fn a_parameter_expansion_with_a_command_substitution_can_run_cargo() {
    assert_rejected(
        "a=car; b=go; : ${x:-$($a$b build)}",
        "a parameter expansion",
    );
    assert_rejected(">${x:-$($a$b build)}", "a redirect");
    assert_rejected("echo ${x:-`$c build`}", "a parameter expansion");
    assert_passes("echo ${x:-y}");
}

#[test]
fn a_short_option_cluster_with_a_glued_value_is_one_option() {
    assert_passes("cargo llvm-cov -j8 --locked");
    assert_passes("cargo llvm-cov -pci-checks --locked");
    assert_rejected("cargo llvm-cov -vj --locked", "short-option cluster");
}

#[test]
fn llvm_cov_nextest_also_reads_the_cargo_options_with_a_value() {
    assert_passes("cargo llvm-cov nextest --target-dir x --locked");
    assert_passes("cargo llvm-cov nextest --message-format json --locked");
    assert_rejected(
        "cargo llvm-cov run --message-format json --locked x",
        "after a positional argument",
    );
}

#[test]
fn more_wrappers_run_their_arguments() {
    for wrapper in [
        "taskset 1",
        "unshare -r",
        "systemd-run --user",
        "chrt 1",
        "nsenter -t 1",
        "runuser -u u --",
        "strace -f",
        "fakeroot",
        "unbuffer",
        "busybox",
    ] {
        assert_rejected(&format!("{wrapper} $c build"), "a parameter expansion");
    }
}

#[test]
fn the_words_of_trap_and_the_quotes_after_find_are_read_as_bash_reads_them() {
    for line in ["trap", "trap -p", "trap -p EXIT", "trap -- 'echo $x' EXIT"] {
        assert_passes(line);
    }
    assert_rejected("trap \\$c EXIT", "a backslash");
    assert_rejected("trap \"\\\"$c\\\" build\" EXIT", "a quote");
    assert_rejected("trap ${c} EXIT", "a parameter expansion");
    assert_rejected("trap \"${c:-\"x\"}\" EXIT", "a quote");
    assert_rejected("trap >/dev/null $c EXIT", "a redirect");
    assert_rejected("trap `$c` EXIT", "a command substitution");
    assert_rejected("trap \"`$c`\" EXIT", "a quote");
    // An escaped quote does not end a double-quoted string, so the `;` ends the command.
    assert_passes("find . -exec rm \"a\\\"b\" ; echo $x");
    assert_rejected("find . -exec rm \"a\\\"b ; echo $x", "a quote");
}

// Review cycle 2.

#[test]
fn a_substitution_in_double_quotes_does_not_hide_the_end_of_the_command() {
    for line in [
        "echo \"${X}\" | xargs echo; echo $Y",
        "mkdir -p \"${OUT}\"; find . -name x -delete; ls $OUT",
        "git diff --name-only \"$(git merge-base HEAD origin/main)\" | xargs -r shellcheck; echo $?",
        "echo \"$(date)\" && find . -name x -delete && echo $HOME",
        "echo \"`date`\" | xargs echo; echo $Y",
        "echo \"${X:-\"a\"}\" | xargs echo; echo $Y",
        "echo \"$(echo \")\")\" | xargs echo; echo $Y",
    ] {
        assert_passes(line);
    }
    // The separator in the substitution is quoted, so the wrapper stays open.
    assert_rejected("xargs echo \"$(echo ;)\" $c build", "a quote");
    assert_rejected(
        "x=car; y=go; find . -exec echo \"$(true)\" ';' -exec $x$y build ';'",
        "a quote",
    );
    assert_rejected("xargs echo \"`echo ;`\" $c build", "a quote");
    assert_rejected("xargs echo \"${x:-;}\" $c build", "a quote");
    // A substitution that the check cannot read to its end makes the rest of the line quoted.
    assert_rejected("xargs echo \"$(echo ; $c build", "a quote");
    assert_rejected(
        "xargs echo \"$(case x in a) echo ;; esac)\" $c build",
        "a quote",
    );
    assert_rejected("xargs echo \"${x:-'}\"; $c build'}\" $c build", "a quote");
    assert_rejected(
        "xargs -I{} sh -c \"$(x)\" ';' $c build",
        "the character '{'",
    );
    assert_rejected("find . -exec sh -c \"${x}\" ';' $c build", "a quote");
    assert_rejected("xargs echo \"$(cat <<x)\" $c build", "a quote");
    assert_passes("echo \"$(echo `date` 'a)' \"b)\")\" | xargs echo; echo $Y");
    assert_passes("echo \"$(echo ${x:-y} \\))\" | xargs echo; echo $Y");
}

#[test]
fn an_argument_of_find_with_only_quoted_expansions_is_one_word() {
    assert_passes("find \"$DIR\"/x -delete");
    assert_passes("find \"$DIR\"/\"$SUB\" -name x");
    assert_rejected("find \"$DIR\"$x -delete", "a quote");
    assert_rejected("find x/$DIR -delete", "a parameter expansion");
    assert_rejected("find \"$(echo x)\"/y $c build", "a quote");
}
