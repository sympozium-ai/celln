#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn workspace() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("celln-cli remains inside the workspace")
}

#[test]
fn provider_and_prompt_shell_metacharacters_stay_inert() {
    let work = tempdir().unwrap();
    let bin_dir = work.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();

    // This is a process, not a mocked Command: celln has to discover it on
    // PATH, construct the real OpenAI provider invocation, wait for it, parse
    // its reply, write the generated source, and hand that source to forge.
    let provider = bin_dir.join("codex");
    std::fs::write(
        &provider,
        r#"#!/bin/sh
set -eu
printf '%s\0' "$@" > "$CELLN_TEST_ARGV"
printf '%s' "$CELLN_TEST_REPLY"
"#,
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&provider).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).unwrap();

    let marker = work.path().join("SHELL_INTERPRETED");
    let decoy = work.path().join("must-survive");
    std::fs::create_dir(&decoy).unwrap();
    std::fs::write(decoy.join("sentinel"), b"still here").unwrap();

    let payload = format!(
        "`touch {marker}` ; rm -rf {decoy} ; touch {marker} && touch {marker} $(touch {marker})",
        marker = marker.display(),
        decoy = decoy.display(),
    );
    // A deliberate compiler error stops before image/KVM setup while proving
    // that provider-controlled source crossed the actual extraction, file,
    // and forge boundary. Its shell syntax must remain bytes throughout.
    let reply = format!("runtime: rust\n```rust\ncompile_error!(r###\"{payload}\"###);\n```\n");
    let argv_log = work.path().join("provider.argv");
    let old_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin_dir.clone()];
    paths.extend(std::env::split_paths(&old_path));
    let path = std::env::join_paths(paths).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_celln"))
        .arg("--root")
        .arg(work.path().join("state"))
        .arg("--no-json")
        .arg("agent")
        .arg(&payload)
        .arg("--provider")
        .arg("openai")
        .arg("--timeout")
        .arg("5")
        .env("PATH", path)
        .env("CELLN_CONFIG", work.path().join("config.toml"))
        .env("CELLN_RUNTIME_DIR", workspace())
        .env("CELLN_TEST_ARGV", &argv_log)
        .env("CELLN_TEST_REPLY", &reply)
        .output()
        .expect("celln agent runs");

    assert!(!output.status.success(), "compile_error! must stop the run");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("generated program does not compile"),
        "provider output must reach forge; stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let raw_argv = std::fs::read(&argv_log).expect("stub provider recorded its argv");
    let argv: Vec<&[u8]> = raw_argv
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    assert_eq!(argv.len(), 5, "unexpected provider argv: {argv:?}");
    let prompt = String::from_utf8_lossy(argv[1]);
    assert!(
        prompt.contains(&payload),
        "task must remain in one prompt argv"
    );

    assert!(
        !marker.exists(),
        "a shell interpreted provider-controlled metacharacters"
    );
    assert!(
        decoy.join("sentinel").is_file(),
        "provider-controlled `rm -rf` was interpreted by a shell"
    );
}
