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
        sources: Vec::new(),
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
    let toolfs = root.path().join("toolfs.ext2");
    std::fs::write(&toolfs, b"test toolfs").unwrap();
    let run = |expected: &str, with_toolfs: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_celln"));
        command
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
            ]);
        if with_toolfs {
            command.arg("--toolfs").arg(&toolfs);
        }
        command.output().unwrap()
    };
    let identity = Hash::of(&bytes).0;
    let accepted = run(&identity, false);
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
    let local = run(&identity, true);
    assert!(
        local.status.success(),
        "{}",
        String::from_utf8_lossy(&local.stderr)
    );
    let local: serde_json::Value = serde_json::from_slice(&local.stdout).unwrap();
    assert_eq!(local["localToolfsVerified"], true);
    assert_eq!(local["localToolfsBytes"], 11);
    assert_eq!(local["artifactReadiness"], "not_checked");
    assert_eq!(local["conformance"], "not_checked");
    assert_eq!(local["scope"], "descriptor-and-local-toolfs-bytes");
    // This intentionally non-ext2 fixture proves only byte identity; no
    // filesystem parsing, executable membership or ABI claim is manufactured.
    std::fs::write(&toolfs, b"tampered").unwrap();
    let tampered = run(&identity, true);
    assert!(!tampered.status.success());
    assert!(tampered.stdout.is_empty());
    std::fs::write(&toolfs, b"test toolfs").unwrap();
    let mismatch = run(&Hash::of(b"wrong").0, false);
    assert!(!mismatch.status.success());
    assert!(mismatch.stdout.is_empty());
    std::fs::write(&policy, serde_json::json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[identity]}).to_string()).unwrap();
    let revoked = run(&identity, true);
    assert!(!revoked.status.success());
    assert!(revoked.stdout.is_empty());
    assert!(!root.path().join("closures").exists());
}
