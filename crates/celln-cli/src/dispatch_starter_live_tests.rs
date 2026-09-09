use super::*;
use std::time::Duration;

#[test]
#[ignore = "explicit billable DeepSeek/KVM native starter toolbox proof"]
fn native_parent_starter_cross_turn_live() {
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
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binaries = repo.join("target/x86_64-unknown-linux-musl/release");
    for name in [
        "celln-harness-parent",
        "celln-harness-turn",
        "celln-pilot",
        "pilot-fetch",
        "celln-workspace-read",
        "celln-workspace-write",
        "celln-https-fetch",
    ] {
        assert!(
            binaries.join(name).exists(),
            "build static guest binary {name} first"
        );
    }
    let work = repo.join(format!(
        "target/starter-live-{}-{}",
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
    let programs = [
        ("/worker", binaries.join("celln-harness-turn")),
        ("/pilot-fetch", binaries.join("pilot-fetch")),
        ("/workspace-read", binaries.join("celln-workspace-read")),
        ("/workspace-write", binaries.join("celln-workspace-write")),
        ("/https-fetch", binaries.join("celln-https-fetch")),
    ];
    let mut worker_request = bundle(&work, &runtime, &kernel, "worker", &programs);
    parent_request.capabilities.timeout_ms = 240000;
    worker_request.capabilities.timeout_ms = 60000;
    std::fs::write(work.join("trusted-motes.json"), json!({"apiVersion":"celln.dev/v1alpha1","bundles":[parent_request.mote.as_ref().unwrap().hash,worker_request.mote.as_ref().unwrap().hash]}).to_string()).unwrap();
    let output = json!({"type":"object","properties":{"revision":{"type":"integer","minimum":0,"maximum":65536},"content":{"type":"string","minLength":0,"maxLength":4096},"error":{"type":"string","minLength":1,"maxLength":1024}},"required":[],"additionalProperties":false}).to_string();
    let schema = |value: String| json!({"hash":Hash::of(value.as_bytes()).0,"bytes":value});
    let specifications = [
        (
            "workspace-read",
            "/workspace-read",
            json!({"type":"object","properties":{"name":{"type":"string","minLength":1,"maxLength":256}},"required":["name"],"additionalProperties":false}),
        ),
        (
            "workspace-write",
            "/workspace-write",
            json!({"type":"object","properties":{"name":{"type":"string","minLength":1,"maxLength":256},"revision":{"type":"integer","minimum":0,"maximum":65536},"content":{"type":"string","minLength":0,"maxLength":4096}},"required":["name","revision","content"],"additionalProperties":false}),
        ),
        (
            "https-fetch",
            "/https-fetch",
            json!({"type":"object","properties":{"url":{"type":"string","minLength":1,"maxLength":2048}},"required":["url"],"additionalProperties":false}),
        ),
    ];
    let tools: Vec<_> = specifications.iter().map(|(name, path, input)| {
        let source = programs.iter().find(|(member, _)| member == path).unwrap();
        json!({"name":name,"path":path,"hash":Hash::of(&std::fs::read(&source.1).unwrap()).0,
            "description":name,"input_schema":schema(input.to_string()),"output_schema":schema(output.clone()),
            "input_bytes":8192,"output_bytes":32768,"timeout_ms":30000})
    }).collect();
    let template = pilot::turn_worker::Template::new(serde_json::from_value(json!({
        "contract":"celln.json-tools/v1","task":"","system":"Execute exactly the tool operation requested on this turn. Never substitute remembered conversation for reading a file. After the tool returns, reply briefly using its result.",
        "url":"https://api.deepseek.com/chat/completions","model":"deepseek-chat","tools":tools,
        "max_turns":3,"max_calls":1,"require_tool_call":true
    })).unwrap()).unwrap();
    let mut binding = super::super::parent_tests::binding(&parent_request);
    binding.incarnation = Hash::of(work.as_os_str().as_encoded_bytes());
    binding.lifetime_ms = 240000;
    binding.turn_timeout_ms = 60000;
    binding.turn_model_requests = 3;
    binding.turn_output_tokens = 1536;
    binding.max_turns = 3;
    binding.total_model_requests = 9;
    binding.total_output_tokens = 4608;
    let profile = serde_json::to_vec(&json!({"apiVersion":"celln.parent-model-profile/v1","principal":binding.principal,
        "requestBinding":worker_request.configuration_binding(celln_spec::ConfigurationRole::Worker).unwrap(),
        "templateBinding":template.binding(),"credentialFile":key.path,"url":template.policy().url,"model":template.policy().model,
        "maxRequests":3,"maxOutputTokens":512,"maxTotalOutputTokens":1536,
        "workspace":{"read":true,"write":true,"maxOperations":4,"maxFiles":8,"maxFileBytes":4096,"maxTotalBytes":16384},
        "fetch":{"allowHosts":["example.com"],"maxRequests":4,"maxResponseBytes":4096,"timeoutMs":10000}
    })).unwrap();
    let profile_hash = Hash::of(&profile);
    std::fs::create_dir(work.join("trusted-parent-models")).unwrap();
    std::fs::write(
        work.join("trusted-parent-models")
            .join(format!("{}.json", &profile_hash.0[7..])),
        profile,
    )
    .unwrap();
    binding.worker_configuration =
        super::super::parent_model::worker_binding(&worker_request, &template, &profile_hash)
            .unwrap();
    if std::env::var("CELLN_INTEROP_STARTER").as_deref() == Ok("true") {
        assert!(std::env::var_os("CELLN_PARENT_INTEROP_BINARY").is_some());
        assert!(std::env::var_os("CELLN_INTEROP_PROVISION_BINARY").is_some());
        let mut catalogue_tools = Vec::new();
        for tool in &template.policy().tools {
            let source = programs
                .iter()
                .find(|(path, _)| *path == tool.path)
                .unwrap();
            let packaged = bundle(
                &work,
                &runtime,
                &kernel,
                &format!("{}-tool", tool.name),
                &[(source.0, source.1.clone())],
            );
            let mut limits = json!({"timeoutMillis":30000,"memoryBytes":268435456u64,"argumentBytes":8192,"outputBytes":32768,"workspace":"none","effects":"none"});
            if tool.name == "https-fetch" {
                limits["effects"] = json!("external-side-effects");
                limits["https"] = json!({"allowHosts":["example.com"],"maxRequests":4,"maxResponseBytes":4096,"timeoutMillis":10000});
            } else {
                let write = tool.name == "workspace-write";
                if write {
                    limits["effects"] = json!("external-side-effects");
                }
                limits["artifacts"] = json!({"operation":if write {"write"} else {"read"},"maxOperations":4,"maxFiles":8,"maxFileBytes":4096,"maxTotalBytes":16384});
            }
            let policy: serde_json::Value =
                serde_json::from_slice(&std::fs::read(work.join("trusted-closures.json")).unwrap())
                    .unwrap();
            catalogue_tools.push(json!({"name":tool.name,"spec":{
                "revision":"v1","description":tool.description,"supportOwner":"isolated-hardware-proof","publisherKey":policy["publishers"][0],
                "executable":{"hash":packaged.tools[0].hash},"closure":packaged.tools[0].closure,
                "entryPoint":tool.path,"invocationABI":"celln.json-stdio/v1",
                "argumentsSchema":{"hash":tool.input_schema.hash},"resultSchema":{"hash":tool.output_schema.hash},
                "platform":"linux/amd64","lane":"tool","limits":limits
            }}));
        }
        let policy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("trusted-closures.json")).unwrap())
                .unwrap();
        std::fs::write(work.join("interop-catalogue.json"), serde_json::to_vec(&json!({
            "systemPrompt":template.policy().system,"tools":catalogue_tools,
            "worker":{"revision":"v1","contractVersion":"celln.json-tools/v1","publisherKey":policy["publishers"][0],
                "executable":{"hash":worker_request.tools[0].hash},"closure":worker_request.tools[0].closure,"mote":worker_request.mote,
                "entryPoint":"/worker","platform":"linux/amd64","lane":"agent","lifecycle":"disposable-one-shot",
                "json":{"maxTurns":3,"maxCalls":1},"limits":{"timeoutMillis":60000,"memoryBytes":268435456u64,"taskBytes":2048,"outputBytes":65536,"workspace":"none"}}
        })).unwrap()).unwrap();
        parent_request.capabilities.timeout_ms = 180000;
        for directory in [
            "parent-issuance",
            "trusted-parent-permits",
            "trusted-parent-launches",
        ] {
            std::fs::create_dir(work.join(directory)).unwrap();
        }
        std::fs::write(work.join("interop-native-template.json"), serde_json::to_vec(&json!({
            "admissionWindowMs":120000,"parent":parent_request,"worker":worker_request,
            "template":template.policy(),"modelProfile":profile_hash,
            "reservedMemoryBytes":2 * (binding.parent_memory_bytes + binding.child_memory_bytes) + (256u64 << 20),
            "maxTurns":2,"turnModelRequests":3,"turnOutputTokens":1536,"totalModelRequests":6,"totalOutputTokens":3072
        })).unwrap()).unwrap();
        crate::dispatch_http::prove_parent_http(
            &work,
            &Hash::of(b"not-pre-issued"),
            &binding.incarnation,
            true,
            false,
        );
        if std::env::var("CELLN_INTEROP_BROWSER_CANCEL").as_deref() != Ok("true") {
            // A held hands-on environment permits user-chosen writes/content.
            // Its joined lifecycle remains checked by prove_parent_http; do
            // not relabel legitimate user turns as failed fixture assertions.
            eprintln!("starter hands-on environment joined: {}", work.display());
            return;
        }
        let mut counts = [0usize; 3];
        for entry in std::fs::read_dir(work.join("parent-audit")).unwrap() {
            let entry = entry.unwrap();
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("worker-proof-")
            {
                continue;
            }
            let proof: serde_json::Value =
                serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap();
            for event in proof["output"]
                .as_str()
                .unwrap_or_default()
                .lines()
                .filter_map(|line| line.strip_prefix("CELLN_HARNESS_EVENT "))
            {
                let event: serde_json::Value = serde_json::from_str(event).unwrap();
                if event["type"] != "tool" {
                    continue;
                }
                assert!(event["result"].get("error").is_none(), "{event}");
                match event["name"].as_str().unwrap() {
                    "workspace-write" => {
                        assert_eq!(event["result"]["revision"], 1);
                        counts[0] += 1;
                    }
                    "workspace-read" => {
                        assert_eq!(event["result"]["content"], "violet");
                        counts[1] += 1;
                    }
                    "https-fetch" => {
                        assert!(event["result"]["content"]
                            .as_str()
                            .unwrap()
                            .contains("Example Domain"));
                        counts[2] += 1;
                    }
                    _ => panic!("unselected tool in starter proof"),
                }
            }
        }
        assert!(
            counts.iter().all(|count| *count > 0),
            "missing starter operations: {counts:?}"
        );
        eprintln!("full-system starter proof: {}", work.display());
        return;
    }
    std::fs::create_dir(work.join("trusted-parent-permits")).unwrap();
    let permit = warden::parent_permit::Permit::issue(binding.clone(), Duration::from_secs(240))
        .unwrap()
        .publish(&work)
        .unwrap();
    let control = celln_control::Control::new(Duration::from_secs(240)).unwrap();
    control.scope(|| {
        let parent = prepare_parent(&parent_request, &work.join("motes"), &work.join("tools"), &work, &permit, &binding, &binding.principal).unwrap();
        let worker = super::super::parent_worker::prepare_worker(&worker_request, template, profile_hash, &binding, &work.join("motes"), &work.join("tools"), &work).unwrap();
        let mut session = parent.into_session(worker).unwrap();
        for (id, task, tool) in [
            ("write", "Call workspace-write with name notes.txt, revision 0, content violet. Report its revision.", "workspace-write"),
            ("read", "Call workspace-read for notes.txt now. Report the content returned by the tool.", "workspace-read"),
            ("fetch", "Call https-fetch for https://example.com/ now. Report the page title returned by the tool.", "https-fetch"),
        ] {
            let result = session.submit(&serde_json::to_vec(&json!({"kind":"turn","apiVersion":pilot::parent_harness::VERSION,"turnId":id,"message":task})).unwrap()).unwrap();
            eprintln!("starter turn {id}: {}", String::from_utf8_lossy(&result));
            let child = Hash::of(&serde_json::to_vec(&(&binding.incarnation.0, id)).unwrap());
            let proof: serde_json::Value = serde_json::from_slice(&std::fs::read(work.join(format!("worker-proof-{}.json", &child.0[7..]))).unwrap()).unwrap();
            assert_eq!(proof["broker"]["denied"], 0, "{proof}");
            let events: Vec<serde_json::Value> = proof["output"].as_str().unwrap().lines().filter_map(|line| line.strip_prefix("CELLN_HARNESS_EVENT ")).map(|line| serde_json::from_str(line).unwrap()).collect();
            let event = events.iter().find(|event| event["type"] == "tool").expect("actual guest tool invocation");
            assert_eq!(event["name"], tool);
            assert!(event["result"].get("error").is_none(), "{event}");
            match id {
                "write" => assert_eq!(event["result"]["revision"], 1),
                "read" => assert_eq!(event["result"]["content"], "violet"),
                "fetch" => assert!(event["result"]["content"].as_str().unwrap().contains("Example Domain")),
                _ => unreachable!(),
            }
        }
        drop(session); // joins/drops the retained parent and its workspace owner
    });
    eprintln!("native starter proof: {}", work.display());
}
