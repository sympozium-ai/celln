#![cfg(feature = "kvm")]

use celln_manifest::{Author, Entry, Hash, Manifest, Tier};
use std::path::{Path, PathBuf};
use std::process::Command;
use warden::vmm::boot::{BootConfig, LinuxCell};

#[test]
fn agent_lane_has_no_linux_capabilities() {
    let Some(kernel) = BootConfig::host_kernel() else {
        eprintln!("skipping: no readable host kernel");
        return;
    };
    if !Path::new("/dev/kvm").exists() {
        eprintln!("skipping: /dev/kvm is absent");
        return;
    }
    if BootConfig::modules_dir_for(&kernel).is_none() {
        eprintln!("skipping: no matching modules for {}", kernel.display());
        return;
    }
    if !musl_target_installed() {
        eprintln!("skipping: x86_64-unknown-linux-musl is not installed");
        return;
    }

    let root = repo_root();
    let work = std::env::temp_dir().join(format!("celln-capability-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();

    let probe = work.join("capability-probe");
    assert!(
        Command::new("rustc")
            .current_dir(&root)
            .args([
                "--edition",
                "2021",
                "-O",
                "--target",
                "x86_64-unknown-linux-musl",
                "-C",
                "target-feature=+crt-static",
                "-o",
            ])
            .arg(&probe)
            .arg(root.join("crates/celln-pilot/tests/fixtures/capability_probe.rs"))
            .status()
            .unwrap()
            .success(),
        "guest capability probe did not compile"
    );

    let probe_bytes = std::fs::read(&probe).unwrap();
    let mut manifest = Manifest::new();
    manifest.admit(Entry {
        alias: "/capability-probe".into(),
        hash: Hash::of(&probe_bytes),
        tier: Tier::Verified,
        interpreter: false,
        author: Author::Agent,
        recipe: None,
    });
    manifest.sign_standin();
    let manifest_path = work.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let run_path = work.join("run.json");
    std::fs::write(
        &run_path,
        serde_json::to_vec(&serde_json::json!({
            "path": "/capability-probe",
            "alias": "/capability-probe",
            "root": "/tools"
        }))
        .unwrap(),
    )
    .unwrap();

    let toolfs = work.join("toolfs.img");
    run_script(
        &root,
        "scripts/mktoolfs.sh",
        &[toolfs.as_path(), Path::new("32"), &probe],
    );
    let initrd = work.join("initramfs.cpio");
    let output = Command::new(root.join("scripts/mkinitramfs.sh"))
        .current_dir(&root)
        .arg(&initrd)
        .env("CELLN_MANIFEST", &manifest_path)
        .env("CELLN_RUN_JSON", &run_path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mkinitramfs failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = std::fs::read(&toolfs).unwrap();
    let mut cell = LinuxCell::boot(
        BootConfig::new(kernel)
            .with_pmem(payload.len())
            .with_initrd(initrd),
    )
    .unwrap();
    cell.seal_tool(&Hash::of(&payload), &payload).unwrap();
    let report = cell.run().unwrap();
    assert_eq!(
        report.guest_report("pilot_run_/capability-probe"),
        Some("permitted:agent"),
        "probe did not enter the agent lane; console tail:\n{}",
        report.tail(40)
    );
    assert!(
        report
            .console
            .contains("CELLN_CAPABILITY_DROP_OK unshare=EPERM"),
        "unshare(CLONE_NEWNS), which seccomp allows, was not denied by missing CAP_SYS_ADMIN; \
         console tail:\n{}",
        report.tail(40)
    );

    let _ = std::fs::remove_dir_all(work);
}

fn musl_target_installed() -> bool {
    Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .is_ok_and(|out| {
            out.status.success()
                && String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|line| line == "x86_64-unknown-linux-musl")
        })
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("pilot crate must be in the workspace")
        .to_path_buf()
}

fn run_script(root: &Path, script: &str, args: &[&Path]) {
    let status = Command::new(root.join(script))
        .current_dir(root)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "{script} failed");
}
