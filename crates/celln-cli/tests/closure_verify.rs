//! Real CLI proof using a public deterministic test signing seed, no KVM/model.
use celln_manifest::{
    closure::{Closure, Member},
    Hash,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

#[test]
fn cli_verification_is_bound_read_only_and_rechecks_policy() {
    let root = tempfile::tempdir().unwrap();
    let executable = Hash::of(b"test executable").0;
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        toolfs: Hash::of(b"test toolfs").0,
        entrypoint: "/tools/test".into(),
        interpreter: false,
        members: BTreeMap::from([(
            "/tools/test".into(),
            Member {
                hash: executable.clone(),
                dependencies: BTreeSet::new(),
            },
        )]),
    }
    .sign(&[42; 32])
    .unwrap();
    let bytes = serde_json::to_vec_pretty(&signed).unwrap();
    let descriptor = root.path().join("signed.json");
    std::fs::write(&descriptor, &bytes).unwrap();
    let policy = root.path().join("trusted-closures.json");
    std::fs::write(&policy, serde_json::json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[]}).to_string()).unwrap();
    let run = |expected: &str| {
        Command::new(env!("CARGO_BIN_EXE_celln"))
            .arg("--root")
            .arg(root.path())
            .args(["closure", "verify"])
            .arg(&descriptor)
            .args([
                "--expected-hash",
                expected,
                "--publisher",
                &signed.publisher,
                "--entry-point",
                "/tools/test",
                "--executable",
                &executable,
            ])
            .output()
            .unwrap()
    };
    let identity = Hash::of(&bytes).0;
    let accepted = run(&identity);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&accepted.stdout).unwrap();
    assert_eq!(report["apiVersion"], "celln.dev/closure-verification-v1");
    assert_eq!(report["closure"], identity);
    assert_eq!(report["artifactReadiness"], "not_checked");
    assert!(!root.path().join("closures").exists());
    let mismatch = run(&Hash::of(b"wrong").0);
    assert!(!mismatch.status.success());
    assert!(mismatch.stdout.is_empty());
    std::fs::write(&policy, serde_json::json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[identity]}).to_string()).unwrap();
    let revoked = run(&identity);
    assert!(!revoked.status.success());
    assert!(revoked.stdout.is_empty());
    assert!(!root.path().join("closures").exists());
}
