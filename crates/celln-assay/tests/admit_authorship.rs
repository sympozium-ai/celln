use celln_manifest::{resolve_exec_lane, Author, Hash, Input, Lane, Manifest, Tier};
use std::path::Path;
use std::process::{Command, Output};
use tempfile::tempdir;

const ARTIFACT: &[u8] = b"verified artifact bytes";

fn run_admit(root: &Path, file: &Path, alias: &str, agent_authored: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_assay"));
    command
        .arg("--root")
        .arg(root)
        .arg("admit")
        .arg(alias)
        .arg(file);
    if agent_authored {
        command.arg("--agent-authored");
    }
    command.output().expect("assay CLI runs")
}

fn persisted_manifest(root: &Path) -> Manifest {
    let bytes = std::fs::read(root.join("manifest.json")).expect("manifest was persisted");
    serde_json::from_slice(&bytes).expect("persisted manifest parses")
}

#[test]
fn admit_cli_preserves_both_author_modes_and_the_laundering_ban() {
    let work = tempdir().unwrap();
    let artifact = work.path().join("artifact");
    std::fs::write(&artifact, ARTIFACT).unwrap();
    let hash = Hash::of(ARTIFACT);

    let agent_root = work.path().join("agent-store");
    let output = run_admit(&agent_root, &artifact, "/agent/program", true);
    assert!(
        output.status.success(),
        "agent-authored admission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("author=agent"),
        "CLI must report the provenance it persisted"
    );
    let manifest = persisted_manifest(&agent_root);
    assert!(manifest.verify_standin(), "persisted manifest stays signed");
    let entry = manifest.get(&hash).expect("agent entry is present");
    assert_eq!(entry.author, Author::Agent);
    assert_eq!(entry.tier, Tier::Verified);
    assert_eq!(
        resolve_exec_lane(entry, Input::None),
        Lane::Data,
        "verified agent-authored code must not gain tool-lane authority"
    );

    let host_root = work.path().join("host-store");
    let output = run_admit(&host_root, &artifact, "/host/program", false);
    assert!(
        output.status.success(),
        "host-authored admission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("author=host"),
        "CLI must report the provenance it persisted"
    );
    let manifest = persisted_manifest(&host_root);
    assert!(manifest.verify_standin(), "persisted manifest stays signed");
    let entry = manifest.get(&hash).expect("host entry is present");
    assert_eq!(entry.author, Author::Host);
    assert_eq!(entry.tier, Tier::Verified);
    assert_eq!(
        resolve_exec_lane(entry, Input::None),
        Lane::Tool,
        "the default host-authored path must retain its prior authority"
    );
}
