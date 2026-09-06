#[test]
#[cfg(unix)]
fn deepseek_credential_is_stdin_not_argv_and_prompt_stays_data() {
    use std::os::unix::fs::PermissionsExt;
    let work = tempfile::tempdir().unwrap();
    let curl = work.path().join("curl");
    std::fs::write(&curl, r#"#!/usr/bin/env bash
set -euo pipefail
[[ -z "${DEEPSEEK_API_KEY:-}" ]]
[[ "$*" != *synthetic-private-key* ]]
IFS= read -r header
[[ "$header" == 'Authorization: Bearer synthetic-private-key' ]]
while (($#)); do
  if [[ "$1" == -d ]]; then
    jq -e '.model == "deepseek-chat" and .messages[0].content == "quotes: \" ; $(touch forbidden)\nnext line"' <<<"$2" >/dev/null
    break
  fi
  shift
done
printf '%s\n' '{"choices":[{"message":{"content":"SAFE"}}]}' '200'
"#).unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o700)).unwrap();
    let shim = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/deepseek-api");
    let out = std::process::Command::new("bash")
        .arg(shim)
        .arg("quotes: \" ; $(touch forbidden)\nnext line")
        .env(
            "PATH",
            format!(
                "{}:{}",
                work.path().display(),
                std::env::var("PATH").unwrap()
            ),
        )
        .env("DEEPSEEK_API_KEY", "synthetic-private-key")
        .current_dir(work.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"SAFE\n");
    assert!(!work.path().join("forbidden").exists());
}
