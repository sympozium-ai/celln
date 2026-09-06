//! Operator-pinned, immutable declared substrates. Store integrity does not
//! establish trust: only the separate host-owned policy grants admission.

use super::{LaunchOutcome, ResolvedBundle};
use celln_spec::ExecutionRequest;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedMotes {
    api_version: String,
    bundles: Vec<String>,
}

fn authorize(request: &ExecutionRequest, state_root: &Path) -> Result<(), String> {
    let hash = &request.mote.as_ref().ok_or("declared mote required")?.hash;
    let bytes = std::fs::read(state_root.join("trusted-motes.json"))
        .map_err(|_| "declared mote trust policy is unavailable".to_owned())?;
    let policy: TrustedMotes = serde_json::from_slice(&bytes)
        .map_err(|_| "declared mote trust policy is invalid".to_owned())?;
    if policy.api_version != "celln.dev/v1alpha1" || !policy.bundles.contains(hash) {
        return Err("declared mote is not authorized by host policy".into());
    }
    Ok(())
}

/// A pinned bundle cannot undo authority already narrowed on this node.
fn local_agent_constraint(hash: &str, state_root: &Path) -> Result<bool, String> {
    let path = state_root.join("assay/manifest.json");
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("local manifest is unreadable".into()),
    };
    let manifest: celln_manifest::Manifest =
        serde_json::from_slice(&bytes).map_err(|_| "local manifest is invalid".to_owned())?;
    let hash = celln_manifest::Hash(hash.to_owned());
    if manifest.is_revoked(&hash) {
        return Err("declared program is locally revoked".into());
    }
    Ok(manifest
        .get(&hash)
        .is_some_and(|entry| entry.author == celln_manifest::Author::Agent || entry.interpreter))
}

/// Construct only the host-owned invocation file, never executable content.
/// Linux unpacks concatenated newc archives in order. The immutable base must
/// provide a real /celln directory; publisher review of this is part of pinning.
#[cfg(target_os = "linux")]
fn file_archive(name: &str, bytes: &[u8]) -> Vec<u8> {
    fn entry(out: &mut Vec<u8>, name: &str, mode: u32, bytes: &[u8]) {
        let fields = [
            1,
            mode,
            0,
            0,
            1,
            0,
            bytes.len() as u32,
            0,
            0,
            0,
            0,
            (name.len() + 1) as u32,
            0,
        ];
        out.extend_from_slice(b"070701");
        for field in fields {
            out.extend_from_slice(format!("{field:08x}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(bytes);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    let mut archive = Vec::new();
    entry(&mut archive, name, 0o100644, bytes);
    entry(&mut archive, "TRAILER!!!", 0, &[]);
    archive
}

pub(crate) fn launch_declared(
    request: &ExecutionRequest,
    mote_root: &Path,
    tool_root: &Path,
    state_root: &Path,
) -> Result<(LaunchOutcome, ResolvedBundle), String> {
    super::check_supported_authority(request)?;
    authorize(request, state_root)?;
    let inputs = super::inputs::resolve(request, state_root)?;
    let resolved = super::resolve_bundle(request, mote_root, tool_root)?;
    let local_agent = local_agent_constraint(&resolved.program_hash, state_root)?;
    if resolved.format.as_deref() != Some("celln.warm-static-v1") {
        return Err("unsupported declared mote format; expected celln.warm-static-v1".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("sealing cells needs Linux with /dev/kvm".into())
    }
    #[cfg(target_os = "linux")]
    {
        let invocation = request.invocation.as_ref().ok_or("invocation required")?;
        // Artifact bytes remain in memory after verified reads. No mutable
        // store path is reopened between verification and VMM loading.
        let work = crate::agent::tempdir().map_err(|e| e.to_string())?;
        let kernel = work.path().join("kernel");
        let initrd = work.path().join("initrd");
        if !resolved.initrd_bytes.starts_with(b"070701") {
            return Err("unsupported initrd: warm static format requires uncompressed newc".into());
        }
        let run = serde_json::to_vec(&serde_json::json!({
            "path": "/tools/program", "alias": invocation.alias,
            "args": invocation.args, "expected_hash": resolved.program_hash,
            "agent_authored_input": request.execution.lane == celln_spec::RequestedLane::Agent,
            "force_agent_lane": local_agent || request.execution.lane == celln_spec::RequestedLane::Agent,
            "allow_fetch": !request.capabilities.egress.is_empty(),
            "report_output_limit": request.capabilities.output_bytes,
            "workspace_access": request.capabilities.workspace,
            "inputs": inputs,
        }))
        .map_err(|e| e.to_string())?;
        if run.len() > warden::MAX_INVOCATION_BYTES {
            return Err("invocation exceeds bounded delivery channel".into());
        }
        let key = format!(
            "{}:{}",
            resolved.bundle_hash, request.capabilities.memory_bytes
        );
        let mut cell = super::warm::fork(key, vec![resolved.program_hash.clone()], || {
            // The shared template contains no request args, credentials or
            // egress grant. Only enable the post-fork invocation channel.
            let mut initrd_bytes = resolved.initrd_bytes.clone();
            while initrd_bytes.len() % 4 != 0 {
                initrd_bytes.push(0);
            }
            initrd_bytes.extend(file_archive("celln/dispatch-warm", b"pio-v1\n"));
            std::fs::write(&kernel, &resolved.kernel_bytes).map_err(|e| e.to_string())?;
            std::fs::write(&initrd, &initrd_bytes).map_err(|e| e.to_string())?;
            let mut cfg = warden::vmm::boot::BootConfig::new(kernel)
                .with_initrd(initrd)
                .with_pmem(resolved.toolfs_bytes.len());
            cfg.mem_size = request.capabilities.memory_bytes as usize;
            Ok((cfg, resolved.toolfs_bytes.clone()))
        })?;
        cell.set_invocation(&run).map_err(|e| e.to_string())?;
        let outcome = super::run_cell(request, &invocation.alias, cell, state_root)?;
        Ok((outcome, resolved))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_manifest::Hash;
    use celln_store::Store;
    use serde_json::json;

    fn request(mote: &Hash, program: &Hash) -> ExecutionRequest {
        serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1", "id": "substrate-test",
            "workload": { "id": "test", "caller": "test" },
            "mote": { "hash": mote.0 },
            "tools": [{ "alias": "/tools/program", "hash": program.0 }],
            "invocation": { "alias": "/tools/program", "args": ["substrate"] },
            "capabilities": { "workspace": "read-only", "timeoutMs": 8000, "memoryBytes": 268435456, "outputBytes": 1024 },
            "execution": { "lane": "agent", "requireHardwareIsolation": true }
        })).unwrap()
    }

    fn pin(root: &Path, hash: &Hash) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(
            root.join("trusted-motes.json"),
            serde_json::to_vec(&json!({
                "apiVersion": "celln.dev/v1alpha1", "bundles": [hash.0]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn trust_is_separate_from_store_integrity_and_fails_closed() {
        let work = tempfile::tempdir().unwrap();
        let hash = Hash::of(b"bundle");
        let request = request(&hash, &Hash::of(b"program"));
        let missing = work.path().join("must-not-be-opened");
        assert!(launch_declared(&request, &missing, &missing, work.path())
            .unwrap_err()
            .contains("policy is unavailable"));
        pin(work.path(), &Hash::of(b"different bundle"));
        assert!(launch_declared(&request, &missing, &missing, work.path())
            .unwrap_err()
            .contains("not authorized"));
        std::fs::write(work.path().join("trusted-motes.json"), b"{}").unwrap();
        assert!(authorize(&request, work.path())
            .unwrap_err()
            .contains("invalid"));
        assert!(!missing.exists());
        pin(work.path(), &hash);
        assert!(authorize(&request, work.path()).is_ok());
    }

    #[test]
    fn pinned_substrate_cannot_override_local_authority() {
        let work = tempfile::tempdir().unwrap();
        let mut assayer = assay::Assayer::open(work.path().join("assay")).unwrap();
        let hash = assayer
            .admit_verified_authored(
                "/tools/program",
                b"program",
                false,
                celln_manifest::Author::Agent,
            )
            .unwrap();
        assert!(local_agent_constraint(&hash.0, work.path()).unwrap());
        assayer.revoke(&hash);
        assert!(local_agent_constraint(&hash.0, work.path())
            .unwrap_err()
            .contains("revoked"));
    }

    #[test]
    fn a_pin_never_bypasses_artifact_integrity() {
        let work = tempfile::tempdir().unwrap();
        let store = Store::open(work.path().join("motes")).unwrap();
        let tools = Store::open(work.path().join("tools")).unwrap();
        let program = tools.put(b"program").unwrap();
        let kernel = store.put(b"kernel").unwrap();
        let initrd = store.put(b"070701-base").unwrap();
        let toolfs = store.put(b"toolfs").unwrap();
        let bundle = store
            .put(
                &serde_json::to_vec(&json!({
                    "apiVersion": "celln.dev/v1alpha1", "format": "celln.warm-static-v1",
                    "kernel": kernel.0, "initrd": initrd.0, "toolfs": toolfs.0,
                    "invocation": { "alias": "/tools/program", "toolHash": program.0 }
                }))
                .unwrap(),
            )
            .unwrap();
        pin(work.path(), &bundle);
        for hash in [&kernel, &initrd, &toolfs, &bundle] {
            let original = store.get(hash).unwrap();
            let hex = hash.0.strip_prefix("blake3:").unwrap();
            let path = work.path().join("motes/objects").join(&hex[..2]).join(hex);
            std::fs::write(&path, b"altered").unwrap();
            let error = launch_declared(
                &request(&bundle, &program),
                &work.path().join("motes"),
                &work.path().join("tools"),
                work.path(),
            )
            .unwrap_err();
            assert!(error.contains("integrity failure"), "{error}");
            std::fs::write(path, original).unwrap();
        }
        assert_eq!(crate::cells::live_count(work.path()), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn declared_request_cannot_use_the_host_rebuilding_launcher() {
        let work = tempfile::tempdir().unwrap();
        let request = request(&Hash::of(b"mote"), &Hash::of(b"program"));
        let missing = work.path().join("unused");
        assert!(super::super::launch(
            &request,
            "/tools/program",
            &[],
            b"program",
            &missing,
            &missing,
            &missing
        )
        .unwrap_err()
        .contains("pinned substrate launcher"));
        assert!(!missing.exists());
    }

    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "needs real KVM, readable kernel, static pilot, and initramfs toolchain"]
    fn declared_substrate_on_real_kvm() {
        let _proof = super::super::warm::PROOF_LOCK.lock().unwrap();
        use std::process::Command;
        if !Path::new("/dev/kvm").exists() {
            eprintln!("SKIP: no KVM");
            return;
        }
        let Some(kernel) = warden::vmm::boot::BootConfig::host_kernel() else {
            eprintln!("SKIP: no readable kernel");
            return;
        };
        for tool in ["gcc", "cpio", "mkfs.ext2", "debugfs", "rustc"] {
            if Command::new("sh")
                .args(["-c", "command -v \"$1\"", "check", tool])
                .output()
                .map_or(true, |o| !o.status.success())
            {
                eprintln!("SKIP: missing {tool}");
                return;
            }
        }
        let work = tempfile::tempdir().unwrap();
        let Some(runtime) = super::super::tests::test_runtime_root(work.path()) else {
            return;
        };
        let program = work.path().join("program");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dispatch_outcome_probe.rs");
        let build = Command::new("rustc")
            .args(["--edition=2021", "--target", "x86_64-unknown-linux-musl"])
            .arg(&source)
            .arg("-o")
            .arg(&program)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let program_bytes = std::fs::read(&program).unwrap();
        let assay_root = work.path().join("assay");
        let mut assayer = assay::Assayer::open(&assay_root).unwrap();
        let program_hash = assayer
            .admit_verified_authored(
                "/tools/program",
                &program_bytes,
                false,
                celln_manifest::Author::Host,
            )
            .unwrap();
        let toolfs = work.path().join("toolfs");
        crate::agent::sh(
            &runtime,
            "scripts/mktoolfs.sh",
            &[
                toolfs.display().to_string(),
                "32".into(),
                program.display().to_string(),
            ],
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
        let mut base = std::fs::read(&initrd).unwrap();
        base.extend(file_archive(
            "celln/work/substrate-marker",
            b"selected-substrate-A\n",
        ));
        let motes = work.path().join("motes");
        let tools = work.path().join("tools");
        let store = Store::open(&motes).unwrap();
        Store::open(&tools).unwrap().put(&program_bytes).unwrap();
        let kernel_hash = store.put(&std::fs::read(kernel).unwrap()).unwrap();
        let initrd_hash = store.put(&base).unwrap();
        let toolfs_hash = store.put(&std::fs::read(toolfs).unwrap()).unwrap();
        let mut bundle = json!({
            "apiVersion": "celln.dev/v1alpha1", "format": "celln.warm-static-v1",
            "kernel": kernel_hash.0, "initrd": initrd_hash.0, "toolfs": toolfs_hash.0,
            "invocation": { "alias": "/tools/program", "toolHash": program_hash.0 }
        });
        let bundle_hash = store.put(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        let state = work.path().join("state");
        pin(&state, &bundle_hash);
        let preparations =
            super::super::warm::PREPARATIONS.load(std::sync::atomic::Ordering::SeqCst);
        let cold_started = std::time::Instant::now();
        let (outcome, resolved) = launch_declared(
            &request(&bundle_hash, &program_hash),
            &motes,
            &tools,
            &state,
        )
        .unwrap();
        assert!(outcome.succeeded(), "{outcome:?}");
        assert_eq!(
            outcome.output.as_deref(),
            Some(b"selected-substrate-A\n".as_slice())
        );
        assert_eq!(resolved.initrd_hash, initrd_hash.0);
        assert_eq!(crate::cells::live_count(&state), 0);
        eprintln!("PASS: declared initrd marker and exact sealed tool execute");
        let hints = super::super::warm::availability().unwrap();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].mote.as_deref(), Some(bundle_hash.0.as_str()));
        assert_eq!(hints[0].tools, vec![program_hash.0.clone()]);
        assert_eq!(hints[0].guest_memory_bytes, 268435456);
        let cold_elapsed = cold_started.elapsed();
        for arg in ["first", "second"] {
            let mut req = request(&bundle_hash, &program_hash);
            req.capabilities.workspace = celln_spec::WorkspaceAccess::ReadWrite;
            req.invocation.as_mut().unwrap().args = vec!["warm".into(), arg.into()];
            let started = std::time::Instant::now();
            let (outcome, _) = launch_declared(&req, &motes, &tools, &state).unwrap();
            assert!(outcome.succeeded(), "{outcome:?}");
            assert_eq!(
                outcome.output.as_deref(),
                Some(format!("warm:{arg}\n").as_bytes())
            );
            assert_eq!(
                super::super::warm::PREPARATIONS.load(std::sync::atomic::Ordering::SeqCst),
                preparations + 1
            );
            eprintln!("PASS: warm {arg}, private scratch, distinct args; cold={cold_elapsed:?}, warm={:?}", started.elapsed());
        }

        for (access, name) in [
            (celln_spec::WorkspaceAccess::None, "none"),
            (celln_spec::WorkspaceAccess::ReadOnly, "read-only"),
            (celln_spec::WorkspaceAccess::ReadWrite, "read-write"),
        ] {
            let mut req = request(&bundle_hash, &program_hash);
            req.capabilities.workspace = access;
            // Host-authored manifest tool: this genuinely exercises the
            // tool lane, not an agent-authored tool narrowed back to agent.
            req.execution.lane = celln_spec::RequestedLane::Tool;
            req.invocation.as_mut().unwrap().args = vec!["workspace".into(), name.into()];
            let (outcome, _) = launch_declared(&req, &motes, &tools, &state).unwrap();
            assert!(outcome.succeeded(), "{name}: {outcome:?}");
            assert_eq!(
                outcome.output.as_deref(),
                Some(format!("workspace:{name}\n").as_bytes())
            );
            eprintln!("PASS: guest workspace {name}, root reads and scratch execution denied");
        }
        let mut fetch = request(&bundle_hash, &program_hash);
        fetch.capabilities.egress = vec!["https://example.com".into()];
        fetch.invocation.as_mut().unwrap().args = vec!["fetch-grant".into()];
        let (outcome, _) = launch_declared(&fetch, &motes, &tools, &state).unwrap();
        assert!(outcome.succeeded(), "{outcome:?}");
        assert_eq!(
            outcome.output.as_deref(),
            Some(b"fetch-grant:host-refused-http\n".as_slice())
        );
        eprintln!("PASS: strict helper grant reaches host broker, which refuses plaintext HTTP");
        let input_store = Store::open(state.join("inputs")).unwrap();
        let first = input_store.put(b"first-input").unwrap();
        let second = input_store.put(b"second-input").unwrap();
        std::fs::write(
            state.join("trusted-inputs.json"),
            serde_json::to_vec(&json!({
                "apiVersion": "celln.dev/v1alpha1", "hashes": [first.0, second.0]
            }))
            .unwrap(),
        )
        .unwrap();
        for (hash, data) in [(first, "first-input"), (second, "second-input")] {
            let mut req = request(&bundle_hash, &program_hash);
            req.capabilities.workspace = celln_spec::WorkspaceAccess::ReadWrite;
            req.inputs.push(celln_spec::ExecutionInput {
                name: "data".into(),
                hash: hash.0.clone(),
                media_type: "text/plain".into(),
                bytes: data.len() as u64,
            });
            req.invocation.as_mut().unwrap().args = vec!["inputs".into(), data.into()];
            let (outcome, _) = launch_declared(&req, &motes, &tools, &state).unwrap();
            assert!(outcome.succeeded(), "{outcome:?}");
            assert_eq!(outcome.input_hashes, vec![hash.0]);
            assert_eq!(
                outcome.output.as_deref(),
                Some(format!("inputs:{data}\n").as_bytes())
            );
            assert_eq!(
                super::super::warm::PREPARATIONS.load(std::sync::atomic::Ordering::SeqCst),
                preparations + 1
            );
            eprintln!("PASS: immutable named input {data} delivered on same warm mote");
        }

        // Stop a real running guest without refreshing the end-to-end timer.
        for cancel in [false, true] {
            let control = celln_control::Control::new(std::time::Duration::from_secs(if cancel {
                60
            } else {
                1
            }))
            .unwrap();
            let signal = control.clone();
            let timer = cancel.then(|| {
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    signal.cancel();
                })
            });
            let mut req = request(&bundle_hash, &program_hash);
            req.invocation.as_mut().unwrap().args = vec!["timeout".into()];
            let started = std::time::Instant::now();
            let (outcome, _) = control
                .scope(|| launch_declared(&req, &motes, &tools, &state))
                .unwrap();
            if let Some(timer) = timer {
                timer.join().unwrap();
            }
            assert!(outcome.timed_out && !outcome.succeeded(), "{outcome:?}");
            assert!(String::from_utf8_lossy(outcome.output.as_deref().unwrap())
                .contains("before timeout"));
            assert!(started.elapsed() < std::time::Duration::from_secs(4));
            assert_eq!(crate::cells::live_count(&state), 0);
            assert_eq!(
                control.reason(),
                Some(if cancel {
                    celln_control::Stopped::Cancelled
                } else {
                    celln_control::Stopped::Deadline
                })
            );
            eprintln!("PASS: real guest stopped, cancel={cancel}, no live cell remains");
        }
        let mut cold = request(&bundle_hash, &program_hash);
        cold.capabilities.memory_bytes = 320 << 20; // different cache key
        let control = celln_control::Control::new(std::time::Duration::from_millis(150)).unwrap();
        let result = control.scope(|| launch_declared(&cold, &motes, &tools, &state));
        assert!(result.is_err());
        assert_eq!(control.reason(), Some(celln_control::Stopped::Deadline));
        assert_eq!(crate::cells::live_count(&state), 0);
        eprintln!("PASS: deadline stops cold preparation before cell launch");

        // A pinned bundle whose selected tool hash differs from the sealed
        // file must refuse in pilot, even if that actual file is manifest-admitted.
        let different = Store::open(&tools)
            .unwrap()
            .put(b"different program")
            .unwrap();
        bundle["invocation"]["toolHash"] = json!(different.0);
        let mismatch = store.put(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        pin(&state, &mismatch);
        let (outcome, _) =
            launch_declared(&request(&mismatch, &different), &motes, &tools, &state).unwrap();
        assert_eq!(
            outcome.denial.as_deref(),
            Some("declared program hash mismatch")
        );
        assert!(outcome.output.as_ref().map_or(true, Vec::is_empty));
        assert_eq!(crate::cells::live_count(&state), 0);
        eprintln!("PASS: declared tool mismatch refused by actual guest");

        // Invalid requested kernel bytes must reach the loader, never fall
        // back to a readable host kernel.
        bundle["kernel"] = json!(store.put(b"invalid kernel").unwrap().0);
        let invalid = store.put(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        pin(&state, &invalid);
        assert!(
            launch_declared(&request(&invalid, &different), &motes, &tools, &state)
                .unwrap_err()
                .contains("kernel")
        );
        assert_eq!(crate::cells::live_count(&state), 0);
        eprintln!("PASS: invalid declared kernel never falls back to host");
    }
}
