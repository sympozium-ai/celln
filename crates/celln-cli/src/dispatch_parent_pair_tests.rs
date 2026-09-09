use super::*;
use celln_manifest::{
    closure::{Closure, Member},
    Hash,
};
use celln_store::Store;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

#[path = "../../celln-pilot/src/proof_credential.rs"]
mod credential;

#[path = "dispatch_starter_live_tests.rs"]
mod starter;

fn bundle(
    state: &Path,
    runtime: &Path,
    kernel: &Path,
    name: &str,
    programs: &[(&str, PathBuf)],
) -> ExecutionRequest {
    let rootfs = state.join(format!("{name}-rootfs"));
    std::fs::create_dir_all(rootfs.join("tmp")).unwrap();
    let mut members = BTreeMap::new();
    for (path, source) in programs {
        let bytes = std::fs::read(source).unwrap();
        std::fs::copy(source, rootfs.join(path.trim_start_matches('/'))).unwrap();
        members.insert(
            path.to_string(),
            Member {
                hash: Hash::of(&bytes).0,
                dependencies: BTreeSet::new(),
            },
        );
    }
    members.get_mut(programs[0].0).unwrap().dependencies = programs
        .iter()
        .skip(1)
        .map(|(path, _)| path.to_string())
        .collect();
    let program = std::fs::read(&programs[0].1).unwrap();
    let program_hash = Hash::of(&program);
    let image = state.join(format!("{name}.ext2"));
    let result = std::process::Command::new("mke2fs")
        .args(["-q", "-t", "ext2", "-b", "4096", "-F", "-d"])
        .arg(&rootfs)
        .arg(&image)
        .arg("8192")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let image = std::fs::read(image).unwrap();
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        sources: vec![],
        toolfs: Hash::of(&image).0,
        entrypoint: programs[0].0.into(),
        interpreter: false,
        members,
    }
    .sign(&[31; 32])
    .unwrap();
    let closure = Store::open(state.join("closures"))
        .unwrap()
        .put(&serde_json::to_vec(&signed).unwrap())
        .unwrap();
    std::fs::write(state.join("trusted-closures.json"),json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[]}).to_string()).unwrap();
    let assay_root = state.join(format!("{name}-assay"));
    assay::Assayer::open(&assay_root)
        .unwrap()
        .admit_verified_authored(programs[0].0, &program, false, celln_manifest::Author::Host)
        .unwrap();
    let initrd = state.join(format!("{name}.cpio"));
    crate::agent::sh_env(
        runtime,
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
    let motes = Store::open(state.join("motes")).unwrap();
    Store::open(state.join("tools"))
        .unwrap()
        .put(&program)
        .unwrap();
    let kernel = motes.put(&std::fs::read(kernel).unwrap()).unwrap();
    let initrd = motes.put(&std::fs::read(initrd).unwrap()).unwrap();
    let toolfs = motes.put(&image).unwrap();
    let mote=motes.put(&serde_json::to_vec(&json!({"apiVersion":"celln.dev/v1alpha1","format":"celln.warm-closure-v1",
        "kernel":kernel.0,"initrd":initrd.0,"toolfs":toolfs.0,"invocation":{"alias":programs[0].0,"toolHash":program_hash.0}})).unwrap()).unwrap();
    let mut request = super::parent_tests::request();
    request.id = name.into();
    request.workload.id = name.into();
    request.mote.as_mut().unwrap().hash = mote.0;
    request.tools[0].hash = program_hash.0;
    request.tools[0].alias = programs[0].0.into();
    request.tools[0].closure.as_mut().unwrap().hash = closure.0;
    request.invocation.as_mut().unwrap().alias = programs[0].0.into();
    request
}

#[test]
#[ignore = "explicit billable DeepSeek/KVM proof; requires CELLN_PARENT_MODEL_KEY_FROM_ZSHRC"]
fn declared_parent_worker_pair_real_model() {
    prove_pair(false, false);
}

#[test]
#[ignore = "explicit billable DeepSeek/KVM borrowed-tool proof"]
fn declared_parent_worker_pair_borrowed_tool() {
    prove_pair(true, false);
}

#[test]
#[ignore = "explicit billable DeepSeek/KVM child cancellation proof"]
fn declared_parent_worker_pair_cancelled_model() {
    prove_pair(true, true);
}

fn prove_pair(borrowed: bool, cancel: bool) {
    if cancel {
        assert!(std::env::var_os("CELLN_PARENT_INTEROP_BINARY").is_none());
    }
    let Some(key_path) = std::env::var_os("CELLN_PARENT_MODEL_KEY_FROM_ZSHRC") else {
        eprintln!("SKIP: explicit model key source required");
        return;
    };
    let _proof = crate::dispatch::warm::PROOF_LOCK.lock().unwrap();
    if !Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: no KVM");
        return;
    }
    let Some(kernel) = warden::vmm::boot::BootConfig::host_kernel() else {
        eprintln!("SKIP: no kernel");
        return;
    };
    for tool in ["gcc", "cpio", "mke2fs", "rustc"] {
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
    let binaries = std::env::var_os("CELLN_PILOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("target/x86_64-unknown-linux-musl/release"));
    for name in [
        "celln-harness-parent",
        "celln-harness-turn",
        "celln-pilot",
        "pilot-fetch",
    ] {
        if !binaries.join(name).exists() {
            eprintln!("SKIP: missing {name}");
            return;
        }
    }
    let work = repo.join(format!(
        "target/declared-parent-pair-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&work).unwrap();
    let runtime = crate::dispatch::tests::test_runtime_root(&work).unwrap();
    let key = credential::from_zshrc(Path::new(&key_path)).unwrap();
    let mut parent_request = bundle(
        &work,
        &runtime,
        &kernel,
        "parent",
        &[("/parent", binaries.join("celln-harness-parent"))],
    );
    let mut programs = vec![
        ("/worker", binaries.join("celln-harness-turn")),
        ("/pilot-fetch", binaries.join("pilot-fetch")),
    ];
    if borrowed {
        assert!(std::process::Command::new("rustc")
            .args([
                "--edition=2021",
                "-O",
                "--target",
                "x86_64-unknown-linux-musl",
                "--cfg",
                "uppercase_tool"
            ])
            .arg(repo.join("crates/celln-pilot/tests/fixtures/json_tool.rs"))
            .arg("-o")
            .arg(work.join("uppercase"))
            .status()
            .unwrap()
            .success());
        programs.push(("/uppercase", work.join("uppercase")));
    }
    let mut worker_request = bundle(&work, &runtime, &kernel, "worker", &programs);
    parent_request.capabilities.timeout_ms = 180000;
    worker_request.capabilities.timeout_ms = 60000;
    std::fs::write(work.join("trusted-motes.json"),json!({"apiVersion":"celln.dev/v1alpha1","bundles":[parent_request.mote.as_ref().unwrap().hash,worker_request.mote.as_ref().unwrap().hash]}).to_string()).unwrap();
    let mut config = json!({"contract":"celln.json-tools/v1","task":"",
        "system":"Answer briefly. Remember values supplied in conversation.","url":"https://api.deepseek.com/chat/completions",
        "model":"deepseek-chat","tools":[],"max_turns":1,"max_calls":0});
    if borrowed {
        let schema = r#"{"type":"object","properties":{"text":{"type":"string","minLength":1,"maxLength":64}},"required":["text"],"additionalProperties":false}"#;
        config["system"] = json!("Use the supplied conversation history, including earlier user messages. When the user requests a tool, call it on this turn even if a previous answer is available. Return only the tool result text.");
        config["tools"] = json!([{"name":"uppercase","path":"/uppercase","hash":Hash::of(&std::fs::read(work.join("uppercase")).unwrap()).0,
            "description":"Uppercase text","input_schema":{"bytes":schema,"hash":Hash::of(schema.as_bytes()).0},
            "output_schema":{"bytes":schema,"hash":Hash::of(schema.as_bytes()).0},"input_bytes":1024,"output_bytes":256,"timeout_ms":1000}]);
        config["max_turns"] = json!(3);
        config["max_calls"] = json!(1);
        config["require_tool_call"] = json!(true);
    }
    if borrowed && std::env::var_os("CELLN_PARENT_INTEROP_BINARY").is_some() {
        // Export public catalogue metadata for the exact fixture artifacts.
        // This is neither a host permit nor a claim of OCI compatibility.
        let tool_request = bundle(
            &work,
            &runtime,
            &kernel,
            "uppercase-tool",
            &[("/uppercase", work.join("uppercase"))],
        );
        let policy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("trusted-closures.json")).unwrap())
                .unwrap();
        let publisher = &policy["publishers"][0];
        let catalogue = json!({
            "systemPrompt": config["system"],
            "tool": {
                "revision":"v1", "description":"Uppercase text", "supportOwner":"isolated-hardware-proof", "publisherKey":publisher,
                "executable":{"hash":tool_request.tools[0].hash}, "closure":tool_request.tools[0].closure,
                "entryPoint":"/uppercase", "invocationABI":"celln.json-stdio/v1",
                "argumentsSchema":{"hash":config["tools"][0]["input_schema"]["hash"]},
                "resultSchema":{"hash":config["tools"][0]["output_schema"]["hash"]},
                "platform":"linux/amd64", "lane":"tool",
                "limits":{"timeoutMillis":1000,"memoryBytes":268435456,"argumentBytes":1024,"outputBytes":256,"workspace":"none","effects":"none"}
            },
            "worker": {
                "revision":"v1", "contractVersion":"celln.json-tools/v1", "publisherKey":publisher,
                "executable":{"hash":worker_request.tools[0].hash}, "closure":worker_request.tools[0].closure,
                "mote":worker_request.mote, "entryPoint":"/worker", "platform":"linux/amd64", "lane":"agent", "lifecycle":"disposable-one-shot",
                "json":{"maxTurns":3,"maxCalls":1},
                "limits":{"timeoutMillis":60000,"memoryBytes":268435456,"taskBytes":2048,"outputBytes":65536,"workspace":"none"}
            }
        });
        std::fs::write(
            work.join("interop-catalogue.json"),
            serde_json::to_vec(&catalogue).unwrap(),
        )
        .unwrap();
    }
    let template =
        pilot::turn_worker::Template::new(serde_json::from_value(config).unwrap()).unwrap();
    let mut binding = super::parent_tests::binding(&parent_request);
    binding.incarnation = Hash::of(work.as_os_str().as_encoded_bytes());
    binding.turn_timeout_ms = 60000;
    binding.turn_model_requests = if borrowed { 3 } else { 1 };
    binding.turn_output_tokens = binding.turn_model_requests * 512;
    binding.max_turns = if cancel { 3 } else { 2 };
    binding.total_model_requests = binding.max_turns as u64 * binding.turn_model_requests;
    binding.total_output_tokens = binding.max_turns as u64 * binding.turn_output_tokens;
    let profile = json!({"apiVersion":"celln.parent-model-profile/v1","principal":binding.principal,
        "requestBinding":worker_request.configuration_binding(celln_spec::ConfigurationRole::Worker).unwrap(),
        "templateBinding":template.binding(),"credentialFile":key.path,"url":template.policy().url,"model":template.policy().model,
        "maxRequests":binding.turn_model_requests,"maxOutputTokens":512,"maxTotalOutputTokens":binding.turn_output_tokens});
    let profile = serde_json::to_vec(&profile).unwrap();
    let profile_hash = Hash::of(&profile);
    std::fs::create_dir(work.join("trusted-parent-models")).unwrap();
    std::fs::write(
        work.join("trusted-parent-models")
            .join(format!("{}.json", &profile_hash.0[7..])),
        profile,
    )
    .unwrap();
    binding.worker_configuration =
        super::parent_model::worker_binding(&worker_request, &template, &profile_hash).unwrap();
    let automatic = std::env::var_os("CELLN_INTEROP_PROVISION_BINARY").is_some();
    let reuse = std::env::var("CELLN_INTEROP_REUSE_TEMPLATE").as_deref() == Ok("true");
    if reuse {
        assert!(automatic);
    }
    if automatic {
        assert!(std::env::var_os("CELLN_PARENT_INTEROP_BINARY").is_some());
        for directory in [
            "parent-issuance",
            "trusted-parent-permits",
            "trusted-parent-launches",
        ] {
            std::fs::create_dir(work.join(directory)).unwrap();
        }
        std::fs::write(work.join("interop-native-template.json"), serde_json::to_vec(&json!({
            "admissionWindowMs":120000, "parent":parent_request, "worker":worker_request,
            "template":template.policy(), "modelProfile":profile_hash,
            "reservedMemoryBytes":2 * (binding.parent_memory_bytes + binding.child_memory_bytes) + (256u64 << 20),
            "maxTurns":binding.max_turns, "turnModelRequests":binding.turn_model_requests,
            "turnOutputTokens":binding.turn_output_tokens, "totalModelRequests":binding.total_model_requests,
            "totalOutputTokens":binding.total_output_tokens
        })).unwrap()).unwrap();
    }
    let launch_hash = if automatic {
        Hash::of(b"not-pre-issued")
    } else {
        let permit = warden::parent_permit::Permit::issue(
            binding.clone(),
            std::time::Duration::from_secs(120),
        )
        .unwrap();
        std::fs::create_dir(work.join("trusted-parent-permits")).unwrap();
        let permit_hash = permit.publish(&work).unwrap();
        let launch = serde_json::to_vec(&json!({"apiVersion":"celln.parent-launch/v1",
        "parent":parent_request,"worker":worker_request,"template":template.policy(),
        "modelProfile":profile_hash,"permit":permit_hash,"binding":binding,
        "reservedMemoryBytes":2 * (binding.parent_memory_bytes + binding.child_memory_bytes) + (256u64 << 20)
    })).unwrap();
        std::fs::create_dir(work.join("trusted-parent-launches")).unwrap();
        let launch_hash = parent_create::publish(&work, &launch, &binding.principal).unwrap();
        assert!(parent_create::admit(&work, &launch_hash, "another-tenant").is_err());
        launch_hash
    };
    let evidence = crate::dispatch_http::prove_parent_http(
        &work,
        &launch_hash,
        &binding.incarnation,
        borrowed,
        cancel,
    );
    if automatic {
        let provisioned: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("interop-provisioned.json")).unwrap())
                .unwrap();
        binding.incarnation = serde_json::from_value(provisioned["incarnation"].clone()).unwrap();
        let uid = provisioned["runUID"].as_str().unwrap();
        assert_eq!(
            binding.incarnation,
            warden::parent_permit::run_incarnation("kind-celln-deployed-live-proof", uid).unwrap()
        );
        for directory in [
            "parent-issuance",
            "trusted-parent-permits",
            "trusted-parent-launches",
        ] {
            let count = std::fs::read_dir(work.join(directory)).unwrap().count();
            if std::env::var_os("CELLN_INTEROP_HOLD_SECONDS").is_some() {
                // Two proof parents plus the fresh hands-on parent. Users may
                // create further runs in the isolated supervised namespace.
                assert!(count >= 3, "missing hands-on authority record");
            } else {
                assert_eq!(count, if reuse { 2 } else { 1 });
            }
        }
    }
    let mut children = Vec::new();
    assert_eq!(evidence.len(), 2);
    let mut turns: Vec<_> = evidence
        .iter()
        .cloned()
        .map(|result| (binding.incarnation.clone(), result))
        .collect();
    if reuse {
        let second: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("interop-reused.json")).unwrap())
                .unwrap();
        let parent: Hash = serde_json::from_value(second["incarnation"].clone()).unwrap();
        assert_ne!(parent, binding.incarnation);
        assert_eq!(
            parent,
            warden::parent_permit::run_incarnation(
                "kind-celln-deployed-live-proof",
                second["runUID"].as_str().unwrap()
            )
            .unwrap()
        );
        assert_eq!(second["templateUnchanged"], true);
        let results = second["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        turns.extend(
            results
                .iter()
                .cloned()
                .map(|result| (parent.clone(), result)),
        );
    }
    for (parent, result) in &turns {
        let id = result["turnId"].as_str().unwrap();
        let warden::parent_journal::TurnStatus::ParentCommitted(record) =
            warden::parent_journal::inspect_turn(&work.join("parent-journal"), parent, id).unwrap()
        else {
            panic!("missing commit")
        };
        let audit_root = if std::env::var_os("CELLN_INTEROP_DISPATCHER_BINARY").is_some() {
            work.join("parent-audit")
        } else {
            work.clone()
        };
        let proof: serde_json::Value = serde_json::from_slice(
            &std::fs::read(audit_root.join(format!("worker-proof-{}.json", &record.child.0[7..])))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(proof["broker"]["requests"], if borrowed { 2 } else { 1 });
        assert_eq!(proof["broker"]["denied"], 0);
        let events: Vec<serde_json::Value> = proof["output"]
            .as_str()
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix("CELLN_HARNESS_EVENT "))
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let tools: Vec<_> = events
            .iter()
            .filter(|event| event["type"] == "tool")
            .collect();
        assert_eq!(tools.len(), usize::from(borrowed));
        if borrowed {
            assert_eq!(tools[0]["name"], "uppercase");
            assert_eq!(
                tools[0]["hash"],
                Hash::of(&std::fs::read(work.join("uppercase")).unwrap()).0
            );
            assert_eq!(tools[0]["arguments"]["text"], "violet");
            assert_eq!(tools[0]["result"]["text"], "VIOLET");
            assert_eq!(
                events
                    .iter()
                    .find(|event| event["type"] == "completed")
                    .unwrap()["calls"],
                1
            );
        }
        children.push(record.child);
    }
    assert_ne!(children[0], children[1]);
    assert_eq!(
        children
            .iter()
            .map(|child| &child.0)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        children.len()
    );
    std::fs::write(
        work.join("pair-results.json"),
        serde_json::to_vec_pretty(
            &json!({"results":evidence,"children":children,"ownerJoined":true,"borrowedUppercase":borrowed}),
        )
        .unwrap(),
    )
    .unwrap();
    let credential_path = key.path.clone();
    drop(key);
    assert!(!credential_path.exists());
    eprintln!("PASS: declared signed parent + worker, per-child broker, real retained model context, joined teardown. Evidence: {}",work.display());
}
