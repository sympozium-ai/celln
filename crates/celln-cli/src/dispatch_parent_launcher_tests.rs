use super::*;
use celln_manifest::{
    closure::{Closure, Member},
    Hash,
};
use celln_store::Store;
use serde_json::json;

pub(super) fn binding(request: &ExecutionRequest) -> warden::parent_permit::Binding {
    warden::parent_permit::Binding {
        principal: request.workload.caller.clone(),
        incarnation: Hash::of(b"launcher-test"),
        parent_configuration: request
            .configuration_binding(celln_spec::ConfigurationRole::Parent)
            .unwrap(),
        worker_configuration: Hash::of(b"separately-admitted-worker"),
        parent_memory_bytes: request.capabilities.memory_bytes,
        child_memory_bytes: 268435456,
        lifetime_ms: request.capabilities.timeout_ms,
        turn_timeout_ms: 1000,
        max_turns: 2,
        turn_model_requests: 0,
        turn_output_tokens: 0,
        total_model_requests: 0,
        total_output_tokens: 0,
    }
}

pub(super) fn request() -> ExecutionRequest {
    serde_json::from_value(json!({"apiVersion":"celln.dev/v1alpha1","id":"parent-launcher",
        "workload":{"id":"parent-launcher","caller":"test:parent"},
        "mote":{"hash":Hash::of(b"mote").0},
        "tools":[{"alias":"/parent","hash":Hash::of(b"parent").0,"closure":{"hash":Hash::of(b"closure").0}}],
        "invocation":{"alias":"/parent","args":[]},
        "capabilities":{"workspace":"none","timeoutMs":30000,"memoryBytes":268435456,"outputBytes":8192},
        "execution":{"lane":"agent","requireHardwareIsolation":true}})).unwrap()
}

#[test]
fn parent_contract_refuses_ambient_authority_even_with_matching_fingerprint() {
    let request = request();
    assert!(validate_parent_request(&request, &binding(&request)).is_ok());
    for (path, value) in [
        ("/capabilities/workspace", json!("read-only")),
        ("/capabilities/egress", json!(["https://api.deepseek.com"])),
        ("/execution/lane", json!("tool")),
        ("/execution/requireHardwareIsolation", json!(false)),
        ("/invocation/args", json!(["unexpected"])),
    ] {
        let mut changed = serde_json::to_value(&request).unwrap();
        *changed.pointer_mut(path).unwrap() = value;
        let changed: ExecutionRequest = serde_json::from_value(changed).unwrap();
        assert!(
            validate_parent_request(&changed, &binding(&changed)).is_err(),
            "{path}"
        );
    }
    let root = tempfile::tempdir().unwrap();
    assert!(prepare_parent(
        &request,
        root.path(),
        root.path(),
        root.path(),
        &Hash::of(b"missing"),
        &binding(&request),
        "test:parent"
    )
    .is_err());
}

#[test]
#[ignore = "requires real KVM, kernel, static native parent/Pilot and initramfs tools"]
fn declared_parent_launcher_on_real_kvm() {
    let _proof = crate::dispatch::warm::PROOF_LOCK.lock().unwrap();
    if !Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: no KVM");
        return;
    }
    let Some(kernel) = warden::vmm::boot::BootConfig::host_kernel() else {
        eprintln!("SKIP: no kernel");
        return;
    };
    for tool in ["gcc", "cpio", "mke2fs"] {
        if std::process::Command::new("sh")
            .args(["-c", "command -v \"$1\"", "check", tool])
            .output()
            .map_or(true, |output| !output.status.success())
        {
            eprintln!("SKIP: missing {tool}");
            return;
        }
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pilot_dir = std::env::var_os("CELLN_PILOT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| repo.join("target/x86_64-unknown-linux-musl/release"));
    if !pilot_dir.join("celln-harness-parent").exists() {
        eprintln!("SKIP: native parent not built");
        return;
    }
    let work = tempfile::tempdir().unwrap();
    let Some(runtime) = crate::dispatch::tests::test_runtime_root(work.path()) else {
        return;
    };
    let rootfs = work.path().join("rootfs");
    std::fs::create_dir(&rootfs).unwrap();
    std::fs::create_dir(rootfs.join("tmp")).unwrap();
    let program = std::fs::read(pilot_dir.join("celln-harness-parent")).unwrap();
    let program_hash = Hash::of(&program);
    std::fs::copy(
        pilot_dir.join("celln-harness-parent"),
        rootfs.join("parent"),
    )
    .unwrap();
    let image = work.path().join("toolfs.ext2");
    let output = std::process::Command::new("mke2fs")
        .args(["-q", "-t", "ext2", "-b", "4096", "-F", "-d"])
        .arg(&rootfs)
        .arg(&image)
        .arg("8192")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let image = std::fs::read(image).unwrap();
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        sources: vec![],
        toolfs: Hash::of(&image).0,
        entrypoint: "/parent".into(),
        interpreter: false,
        members: std::collections::BTreeMap::from([(
            "/parent".into(),
            Member {
                hash: program_hash.0.clone(),
                dependencies: Default::default(),
            },
        )]),
    }
    .sign(&[29; 32])
    .unwrap();
    let state = work.path().join("state");
    let closure = Store::open(state.join("closures"))
        .unwrap()
        .put(&serde_json::to_vec(&signed).unwrap())
        .unwrap();
    std::fs::write(state.join("trusted-closures.json"), json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[]}).to_string()).unwrap();
    let mut assay = assay::Assayer::open(state.join("assay")).unwrap();
    assay
        .admit_verified_authored("/parent", &program, false, celln_manifest::Author::Host)
        .unwrap();
    let initrd = work.path().join("initrd");
    crate::agent::sh_env(
        &runtime,
        "scripts/mkinitramfs.sh",
        &[initrd.display().to_string()],
        &[
            (
                "CELLN_MANIFEST",
                state.join("assay/manifest.json").display().to_string(),
            ),
            (
                "CELLN_PILOT_DIR",
                runtime.join("pilot").display().to_string(),
            ),
        ],
    )
    .unwrap();
    let motes = Store::open(state.join("motes")).unwrap();
    Store::open(state.join("tools"))
        .unwrap()
        .put(&program)
        .unwrap();
    let kernel = motes.put(&std::fs::read(kernel).unwrap()).unwrap();
    let initrd = motes.put(&std::fs::read(initrd).unwrap()).unwrap();
    let toolfs = motes.put(&image).unwrap();
    let mote = motes.put(&serde_json::to_vec(&json!({"apiVersion":"celln.dev/v1alpha1","format":"celln.warm-closure-v1",
        "kernel":kernel.0,"initrd":initrd.0,"toolfs":toolfs.0,"invocation":{"alias":"/parent","toolHash":program_hash.0}})).unwrap()).unwrap();
    std::fs::write(
        state.join("trusted-motes.json"),
        json!({"apiVersion":"celln.dev/v1alpha1","bundles":[mote.0]}).to_string(),
    )
    .unwrap();
    let mut request = request();
    request.mote.as_mut().unwrap().hash = mote.0;
    request.tools[0].hash = program_hash.0;
    request.tools[0].closure.as_mut().unwrap().hash = closure.0;
    let binding = binding(&request);
    let clock = warden::parent_permit::host_clock().unwrap();
    let permit = warden::parent_permit::Permit {
        api_version: warden::parent_permit::VERSION.into(),
        binding: binding.clone(),
        boot_id: clock.boot_id,
        issued_at_boottime_ms: clock.boottime_ms,
        expires_at_boottime_ms: clock.boottime_ms + 60000,
    };
    let permit = serde_json::to_vec(&permit).unwrap();
    let permit_hash = Hash::of(&permit);
    std::fs::create_dir(state.join("trusted-parent-permits")).unwrap();
    let permit_path = state
        .join("trusted-parent-permits")
        .join(format!("{}.json", &permit_hash.0[7..]));
    std::fs::write(&permit_path, &permit).unwrap();
    let prepare = || {
        prepare_parent(
            &request,
            &state.join("motes"),
            &state.join("tools"),
            &state,
            &permit_hash,
            &binding,
            "test:parent",
        )
        .unwrap()
    };
    let revoked = prepare();
    std::fs::remove_file(&permit_path).unwrap();
    assert!(revoked.launch().is_err());
    std::fs::write(&permit_path, &permit).unwrap();
    let mut parent = prepare().launch().unwrap();
    let mut exchange = |input: serde_json::Value| {
        parent
            .cell
            .deliver_parent_message(&serde_json::to_vec(&input).unwrap())
            .unwrap();
        let report = parent.cell.run().unwrap();
        assert_eq!(
            report.end,
            warden::vmm::boot::BootEnd::Parked,
            "{}",
            report.tail(30)
        );
        assert!(!report.console.contains("Linux version"));
        serde_json::from_slice::<serde_json::Value>(
            &parent.cell.take_parent_response().unwrap().unwrap(),
        )
        .unwrap()
    };
    let spawn = exchange(
        json!({"kind":"turn","apiVersion":pilot::parent_harness::VERSION,"turnId":"one","message":"remember violet"}),
    );
    assert_eq!(spawn["kind"], "spawn");
    let completed = exchange(
        json!({"kind":"result","apiVersion":pilot::parent_harness::VERSION,"turnId":"one","succeeded":true,"answer":"remembered"}),
    );
    assert_eq!(completed["kind"], "completed");
    let next = exchange(
        json!({"kind":"turn","apiVersion":pilot::parent_harness::VERSION,"turnId":"two","message":"what value?"}),
    );
    let task: serde_json::Value =
        serde_json::from_str(next["request"]["task"].as_str().unwrap()).unwrap();
    assert_eq!(task["history"][0]["user"], "remember violet");
    assert!(prepare().launch().is_err());
    drop(parent);
    eprintln!("PASS: signed declared parent, permit revocation before fork, retained guest context, incarnation replay refused");
}
