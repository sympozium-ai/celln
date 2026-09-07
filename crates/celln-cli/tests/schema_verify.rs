use celln_manifest::Hash;
use std::process::Command;

#[test]
fn cli_binds_schema_and_requires_explicit_value_budget() {
    let dir = tempfile::tempdir().unwrap();
    let schema = dir.path().join("schema.json");
    let value = dir.path().join("value.json");
    let bytes = br#"{"type":"integer","minimum":0,"maximum":42}"#;
    std::fs::write(&schema, bytes).unwrap();
    std::fs::write(&value, b"42").unwrap();
    let run = |hash: &str, budget: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_celln"));
        command
            .args(["schema", "verify"])
            .arg(&schema)
            .args(["--expected-hash", hash, "--value"])
            .arg(&value);
        if let Some(budget) = budget {
            command.args(["--max-value-bytes", budget]);
        }
        command.output().unwrap()
    };
    let hash = Hash::of(bytes).0;
    let success = run(&hash, Some("2"));
    assert!(
        success.status.success(),
        "{}",
        String::from_utf8_lossy(&success.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&success.stdout).unwrap();
    assert_eq!(report["schema"], hash);
    assert_eq!(report["valueValidated"], true);
    assert_eq!(report["scope"], "schema-and-data-only");
    for budget in [None, Some("0"), Some("1"), Some("65537")] {
        let refused = run(&hash, budget);
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
    }
    assert!(!run(&Hash::of(b"wrong").0, Some("2")).status.success());
    std::fs::write(&value, b"43").unwrap();
    let refused = run(&hash, Some("2"));
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}
