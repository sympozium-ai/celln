#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn celln_with_umask(xdg: &Path, args: &[&str], path: Option<&Path>) -> Output {
    let binary = env!("CARGO_BIN_EXE_celln");
    let mut command = Command::new("sh");
    command
        .args(["-c", "umask 000; exec \"$@\"", "celln", binary])
        .args(args)
        .env("XDG_CONFIG_HOME", xdg)
        .env("HOME", xdg.parent().expect("XDG config parent"));
    if let Some(path) = path {
        command.env("PATH", path);
    }
    command.output().expect("run celln")
}

fn config_path(xdg: &Path) -> PathBuf {
    xdg.join("celln/config.toml")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "celln failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_mode_0600(path: &Path) {
    let mode = fs::metadata(path)
        .expect("config metadata")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(mode, 0o600, "unexpected mode for {}", path.display());
}

#[test]
fn providers_creates_config_with_mode_0600_despite_permissive_umask() {
    let home = tempfile::tempdir().expect("temporary home");
    let xdg = home.path().join("config");

    let output = celln_with_umask(&xdg, &["providers", "--set-default", "local"], None);

    assert_success(&output);
    assert_mode_0600(&config_path(&xdg));
}

#[test]
fn setup_tightens_an_existing_config_to_mode_0600() {
    let home = tempfile::tempdir().expect("temporary home");
    let xdg = home.path().join("config");
    let config = config_path(&xdg);
    fs::create_dir_all(config.parent().expect("config parent")).expect("create config dir");
    fs::write(&config, "[provider]\ndefault = \"openai\"\n").expect("seed config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).expect("set loose mode");

    let bin = home.path().join("bin");
    fs::create_dir(&bin).expect("create fake bin dir");
    let ollama = bin.join("ollama");
    fs::write(&ollama, "#!/bin/sh\nexit 0\n").expect("write fake ollama");
    fs::set_permissions(&ollama, fs::Permissions::from_mode(0o755)).expect("make fake executable");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let state = home.path().join("state");
    let output = celln_with_umask(
        &xdg,
        &[
            "--root",
            state.to_str().expect("UTF-8 state path"),
            "setup",
            "--provider",
            "local",
            "--no-tools",
        ],
        Some(Path::new(&path)),
    );

    assert_success(&output);
    assert_mode_0600(&config);
    assert!(fs::read_to_string(config)
        .expect("read rewritten config")
        .contains("default = \"local\""));
}
