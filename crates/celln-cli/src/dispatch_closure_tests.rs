use super::*;
use celln_manifest::{
    closure::{Closure, Member},
    Hash,
};
use celln_store::Store;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

fn command(cmd: &mut Command) -> Vec<u8> {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

#[test]
#[ignore = "requires real KVM, native Rust linker, static pilot and initramfs tools"]
fn signed_closure_on_real_kvm() {
    let _proof = super::super::warm::PROOF_LOCK.lock().unwrap();
    if !Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: no KVM");
        return;
    }
    let Some(kernel) = warden::vmm::boot::BootConfig::host_kernel() else {
        eprintln!("SKIP: no kernel");
        return;
    };
    for tool in ["rustc", "ldd", "gcc", "cpio", "mke2fs", "debugfs"] {
        if Command::new("sh")
            .args(["-c", "command -v \"$1\"", "check", tool])
            .output()
            .map_or(true, |out| !out.status.success())
        {
            eprintln!("SKIP: missing {tool}");
            return;
        }
    }
    let work = tempfile::tempdir().unwrap();
    let Some(runtime) = super::super::tests::test_runtime_root(work.path()) else {
        return;
    };
    let started = std::time::Instant::now();
    let rootfs = work.path().join("rootfs");
    for dir in ["bin", "lib64", "tmp", "etc"] {
        std::fs::create_dir_all(rootfs.join(dir)).unwrap();
    }
    let program = rootfs.join("bin/program");
    command(
        Command::new("rustc")
            .args(["--edition=2021", "-O"])
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/closure_probe.rs"))
            .arg("-o")
            .arg(&program),
    );
    // Packaging-only inspection of our freshly compiled fixture. Dispatch
    // never runs ldd or opens host libraries; it consumes signed sealed bytes.
    let linked = command(Command::new("ldd").arg(&program));
    let mut members = BTreeMap::new();
    for word in String::from_utf8(linked)
        .unwrap()
        .split_whitespace()
        .filter(|s| s.starts_with('/'))
    {
        let path = Path::new(word);
        let bytes = std::fs::read(path).unwrap();
        let target = rootfs.join(word.trim_start_matches('/'));
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(path, target).unwrap();
        members.insert(
            word.to_owned(),
            Member {
                hash: Hash::of(&bytes).0,
                dependencies: BTreeSet::new(),
            },
        );
    }
    assert!(
        members.len() >= 2,
        "fixture must use an actual dynamic loader and libraries"
    );
    let library = members
        .keys()
        .find(|p| p.contains("libc.so"))
        .unwrap()
        .clone();
    let dependencies = members.keys().cloned().collect();
    let program_bytes = std::fs::read(&program).unwrap();
    let program_hash = Hash::of(&program_bytes);
    members.insert(
        "/bin/program".into(),
        Member {
            hash: program_hash.0.clone(),
            dependencies,
        },
    );
    std::fs::write(rootfs.join("etc/closure-unlisted"), b"not lent").unwrap();
    std::os::unix::fs::symlink("/bin/program", rootfs.join("bin/program-link")).unwrap();
    let image = work.path().join("closure.ext2");
    command(
        Command::new("mke2fs")
            .args(["-q", "-t", "ext2", "-b", "4096", "-F", "-d"])
            .arg(&rootfs)
            .arg(&image)
            .arg("8192"),
    );
    let image_bytes = std::fs::read(&image).unwrap();
    let image_hash = Hash::of(&image_bytes);
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        toolfs: image_hash.0.clone(),
        entrypoint: "/bin/program".into(),
        interpreter: false,
        members,
    }
    .sign(&[17; 32])
    .unwrap();
    let state = work.path().join("state");
    let closure_store = Store::open(state.join("closures")).unwrap();
    let closure_hash = closure_store
        .put(&serde_json::to_vec(&signed).unwrap())
        .unwrap();
    let policy = json!({"apiVersion":"celln.dev/closure-policy-v1", "publishers":[signed.publisher], "revoked":[]});
    std::fs::write(
        state.join("trusted-closures.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let assay_root = state.join("assay");
    let mut assayer = assay::Assayer::open(&assay_root).unwrap();
    assayer
        .admit_verified_authored(
            "/closure/program",
            &program_bytes,
            false,
            celln_manifest::Author::Host,
        )
        .unwrap();
    let initrd = work.path().join("initrd");
    crate::agent::sh_env(
        &runtime,
        "scripts/mkinitramfs.sh",
        &[initrd.display().to_string()],
        &[
            (
                "CELLN_MANIFEST",
                assay_root.join("manifest.json").display().to_string(),
            ),
            (
                "CELLN_PILOT_DIR",
                runtime.join("pilot").display().to_string(),
            ),
        ],
    )
    .unwrap();
    let motes = state.join("motes");
    let tools = state.join("tools");
    let store = Store::open(&motes).unwrap();
    Store::open(&tools).unwrap().put(&program_bytes).unwrap();
    let kernel_hash = store.put(&std::fs::read(kernel).unwrap()).unwrap();
    let initrd_hash = store.put(&std::fs::read(&initrd).unwrap()).unwrap();
    store.put(&image_bytes).unwrap();
    let bundle = store.put(&serde_json::to_vec(&json!({"apiVersion":"celln.dev/v1alpha1", "format":"celln.warm-closure-v1", "kernel":kernel_hash.0,"initrd":initrd_hash.0,"toolfs":image_hash.0,"invocation":{"alias":"/closure/program","toolHash":program_hash.0}})).unwrap()).unwrap();
    std::fs::write(
        state.join("trusted-motes.json"),
        serde_json::to_vec(&json!({"apiVersion":"celln.dev/v1alpha1","bundles":[bundle.0]}))
            .unwrap(),
    )
    .unwrap();
    let materialisation = started.elapsed();
    let mut request: ExecutionRequest = serde_json::from_value(json!({
        "apiVersion":"celln.dev/v1alpha1","id":"closure-proof","workload":{"id":"closure-proof","caller":"test:closure"},
        "mote":{"hash":bundle.0},"tools":[{"alias":"/closure/program","hash":program_hash.0,"closure":{"hash":closure_hash.0}}],
        "invocation":{"alias":"/closure/program","args":["none",library]},
        "capabilities":{"workspace":"none","timeoutMs":15000,"memoryBytes":268435456,"outputBytes":4096},
        "execution":{"lane":"tool","requireHardwareIsolation":true}
    })).unwrap();
    let preparations = super::super::warm::PREPARATIONS.load(std::sync::atomic::Ordering::SeqCst);
    let mut member_request = request.clone();
    member_request.invocation.as_mut().unwrap().args.clear();
    let check_started = std::time::Instant::now();
    let member_report =
        super::super::check_members(&member_request, &motes, &tools, &state).unwrap();
    let member_check_micros = check_started.elapsed().as_micros();
    assert_eq!(member_report["memberIntegrity"], "verified-in-sealed-cell");
    assert_eq!(member_report["memberCount"], signed.closure.members.len());
    assert_eq!(member_report["toolExecution"], false);
    assert_eq!(member_report["artifactReadiness"], "not_checked");
    assert_eq!(member_report["conformance"], "not_checked");
    // Execution arguments cannot turn this read-only operation into a run.
    assert!(super::super::check_members(&request, &motes, &tools, &state).is_err());
    let member_request_file = work.path().join("member-check.json");
    std::fs::write(
        &member_request_file,
        serde_json::to_vec(&member_request).unwrap(),
    )
    .unwrap();
    let binary = std::env::var_os("CELLN_TEST_BINARY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/celln"));
    let cli_bytes = command(
        Command::new(binary)
            .arg("--root")
            .arg(&state)
            .args(["closure", "check-members"])
            .arg(&member_request_file),
    );
    let cli_report: serde_json::Value = serde_json::from_slice(&cli_bytes).unwrap();
    assert_eq!(cli_report["memberIntegrity"], "verified-in-sealed-cell");
    assert_eq!(cli_report["closure"], closure_hash.0);
    assert_eq!(cli_report["toolExecution"], false);
    let mut measurements = Vec::new();
    for mode in ["none", "read-only", "read-write"] {
        request.capabilities.workspace = serde_json::from_value(json!(mode)).unwrap();
        request.invocation.as_mut().unwrap().args[0] = mode.into();
        let start = std::time::Instant::now();
        let (out, _) = super::super::launch_declared(&request, &motes, &tools, &state).unwrap();
        assert!(out.succeeded(), "{out:?}");
        assert_eq!(
            out.output.as_deref(),
            Some(format!("closure:{mode}:dynamic-loader:replacement-denied\n").as_bytes())
        );
        assert_eq!(out.substrate.unwrap().closure.unwrap().hash, closure_hash.0);
        measurements.push(json!({"workspace":mode,"elapsedMicros":start.elapsed().as_micros()}));
    }
    assert_eq!(
        super::super::warm::PREPARATIONS.load(std::sync::atomic::Ordering::SeqCst),
        preparations + 1
    );
    assert_eq!(crate::cells::live_count(&state), 0);
    let mut revoked_cell = super::super::warm::fork(
        format!("{}:268435456", bundle.0),
        vec![program_hash.0.clone()],
        || panic!("warm only"),
    )
    .unwrap();
    revoked_cell
        .set_invocation(
            &serde_json::to_vec(&json!({
                "path":"/bin/program","alias":"/closure/program","root":"/tools",
                "expected_hash":program_hash.0,"closure_members":signed.closure.members,
                "workspace_access":"none","report_output_limit":4096,"args":["revoke",library]
            }))
            .unwrap(),
        )
        .unwrap();
    revoked_cell.set_timeout(std::time::Duration::from_secs(5));
    revoked_cell.revoke_when_guest_prints(&image_hash, "\"kind\":\"output\"");
    let revoked_report = revoked_cell.run().unwrap();
    assert!(revoked_report.revoked_live);
    assert!(
        revoked_report.console.contains("\"kind\":\"signal\""),
        "closure must die on memslot withdrawal, not execute a page-cache copy: {}",
        revoked_report.console
    );
    drop(revoked_cell);
    // A valid publisher cannot substitute the declared library with different
    // bytes inside the sealed image. Pilot checks the actual dependency too.
    let mut bad_member = signed.closure.clone();
    bad_member.members.get_mut(&library).unwrap().hash = Hash::of(b"substituted library").0;
    let bad_member = bad_member.sign(&[17; 32]).unwrap();
    let mut denied = request.clone();
    denied.tools[0].closure.as_mut().unwrap().hash = closure_store
        .put(&serde_json::to_vec(&bad_member).unwrap())
        .unwrap()
        .0;
    let (out, _) = super::super::launch_declared(&denied, &motes, &tools, &state).unwrap();
    member_request.tools = denied.tools.clone();
    assert!(
        super::super::check_members(&member_request, &motes, &tools, &state)
            .unwrap_err()
            .contains("verification failed")
    );
    assert_eq!(
        out.denial.as_deref(),
        Some("sealed closure member mismatch")
    );
    assert!(out.execution.is_none());
    let mut symlink = signed.closure.clone();
    let member = symlink.members.remove("/bin/program").unwrap();
    symlink.entrypoint = "/bin/program-link".into();
    symlink.members.insert(symlink.entrypoint.clone(), member);
    denied.tools[0].closure.as_mut().unwrap().hash = closure_store
        .put(&serde_json::to_vec(&symlink.sign(&[17; 32]).unwrap()).unwrap())
        .unwrap()
        .0;
    let (out, _) = super::super::launch_declared(&denied, &motes, &tools, &state).unwrap();
    assert_eq!(
        out.denial.as_deref(),
        Some("sealed closure member mismatch")
    );
    assert!(out.execution.is_none());
    let mut forged_signature = signed.clone();
    member_request.tools = denied.tools.clone();
    assert!(
        super::super::check_members(&member_request, &motes, &tools, &state)
            .unwrap_err()
            .contains("verification failed")
    );
    forged_signature.signature = celln_manifest::closure::hex(&[0; 64]);
    denied.tools[0].closure.as_mut().unwrap().hash = closure_store
        .put(&serde_json::to_vec(&forged_signature).unwrap())
        .unwrap()
        .0;
    assert!(
        super::super::launch_declared(&denied, &motes, &tools, &state)
            .unwrap_err()
            .contains("signature")
    );
    let mut withdrawn = policy.clone();
    withdrawn["publishers"] = json!([]);
    std::fs::write(
        state.join("trusted-closures.json"),
        serde_json::to_vec(&withdrawn).unwrap(),
    )
    .unwrap();
    assert!(
        super::super::launch_declared(&request, &motes, &tools, &state)
            .unwrap_err()
            .contains("publisher")
    );
    std::fs::write(
        state.join("trusted-closures.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let shared = warden::vmm::kvm::shared_tool_map_existing(&image_hash).unwrap();
    let before_maps = warden::vmm::kvm::shared_tool_count();
    let mut forks = Vec::new();
    for _ in 0..8 {
        forks.push(
            super::super::warm::fork(
                format!("{}:268435456", bundle.0),
                vec![program_hash.0.clone()],
                || panic!("warm only"),
            )
            .unwrap(),
        );
        assert_eq!(
            warden::vmm::kvm::shared_tool_map_existing(&image_hash)
                .unwrap()
                .addr(),
            shared.addr()
        );
    }
    assert_eq!(warden::vmm::kvm::shared_tool_count(), before_maps);
    drop(forks);
    warden::vmm::kvm::collect_unused_tools();
    assert!(
        warden::vmm::kvm::shared_tool_map_existing(&image_hash).is_some(),
        "parked mote must retain its closure"
    );
    let evidence_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../target/closure-proof/{}", std::process::id()));
    std::fs::create_dir_all(&evidence_dir).unwrap();
    crate::dispatch_conformance::prove_closure(&request, &motes, &tools, &state, &evidence_dir);
    let mut revoked = policy.clone();
    revoked["revoked"] = json!([signed.closure.members[&library].hash]);
    std::fs::write(
        state.join("trusted-closures.json"),
        serde_json::to_vec(&revoked).unwrap(),
    )
    .unwrap();
    assert!(
        super::super::launch_declared(&request, &motes, &tools, &state)
            .unwrap_err()
            .contains("revoked")
    );
    let shared_bytes = shared.len();
    let retained = super::super::warm::fork(
        format!("{}:268435456", bundle.0),
        vec![program_hash.0.clone()],
        || panic!("warm only"),
    )
    .unwrap();
    drop(shared);
    super::super::warm::evict();
    assert!(
        warden::vmm::kvm::shared_tool_map_existing(&image_hash).is_some(),
        "live fork must survive cache eviction"
    );
    drop(retained);
    warden::vmm::kvm::collect_unused_tools();
    assert!(
        warden::vmm::kvm::shared_tool_map_existing(&image_hash).is_none(),
        "unused closure backing must be collected after eviction"
    );
    let evidence = json!({"status":"passed","closure":closure_hash.0,"publisher":signed.publisher,"members":signed.closure.members,"toolfsBytes":image_bytes.len(),"materialisationMicros":materialisation.as_micros(),"runs":measurements,"warmPreparations":1,"replacementDenied":true,"dependencyRevocationDenied":true,"signatureForgeryDenied":true,"publisherWithdrawalDenied":true,"memberMismatchDenied":true,"symlinkMemberDenied":true,"daxRevocationKilledGuest":true,"executableScratchMappingDenied":true,"liveForkSurvivedEviction":true,"unusedPagesCollected":true,"simultaneousForks":8,"additionalToolAllocations":0,"sharedToolBytes":shared_bytes});
    let evidence_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/closure-proof");
    let mut evidence = evidence;
    evidence["sealedMemberCheck"] = member_report;
    evidence["sealedMemberCLICheck"] = cli_report;
    evidence["memberCheckIncludingPreparationMicros"] = json!(member_check_micros);
    evidence["executionSamples"] = json!("prewarmed-by-member-check");
    std::fs::create_dir_all(&evidence_dir).unwrap();
    std::fs::write(
        evidence_dir.join(format!("{}.json", std::process::id())),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    eprintln!("PASS: signed dynamic closure, guest replacement attacks, DAX revocation, warm reuse, dependency revocation and GC; {evidence}");
}
