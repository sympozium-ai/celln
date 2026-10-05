//! The starter toolbox on the scoped (mediated) receiver: signed web tool
//! and workspace limits become broker authority without a guest. Hermetic:
//! no public network, KVM or provider; refusals happen before any I/O.
use super::*;

/// A runtime composed with signed tool sources, as Sympozium would select
/// it: the runtime closure first, then one source per tool, in order.
fn toolbox(root: &Path, tools: &[(&str, Value)]) -> (Artifacts, Vec<Value>, Vec<Value>) {
    toolbox_lending(root, tools, &[])
}

/// `toolbox`, followed by borrowed commands (`celln.argv/v1`) whose argv
/// bindings this node reviewed, as `starter-configure` records them.
fn toolbox_lending(
    root: &Path,
    tools: &[(&str, Value)],
    commands: &[&str],
) -> (Artifacts, Vec<Value>, Vec<Value>) {
    use celln_manifest::closure::composition::Source;
    use celln_manifest::closure::{Closure, Member};
    let seed = [7; 32];
    let source = |entry: &str| {
        let signed = Closure {
            api_version: "celln.dev/closure-v1".into(),
            sources: vec![],
            toolfs: Hash::of(format!("toolfs{entry}").as_bytes()).0,
            entrypoint: entry.into(),
            interpreter: false,
            members: BTreeMap::from([(
                entry.into(),
                Member {
                    hash: Hash::of(entry.as_bytes()).0,
                    dependencies: Default::default(),
                },
            )]),
        }
        .sign(&seed)
        .unwrap();
        let descriptor = serde_json::to_string(&signed).unwrap();
        (
            Source {
                hash: Hash::of(descriptor.as_bytes()).0,
                descriptor,
            },
            signed.publisher,
        )
    };
    let (runtime, publisher) = source("/harness");
    let mut sources = vec![runtime];
    for name in tools
        .iter()
        .map(|(name, _)| *name)
        .chain(commands.iter().copied())
    {
        sources.push(source(&format!("/{name}")).0);
    }
    let toolfs = Hash::of(b"scoped-toolbox-toolfs");
    let mut composed =
        celln_manifest::closure::composition::compose(sources.clone(), &toolfs).unwrap();
    composed.api_version = "celln.dev/closure-v2".into();
    composed.sources = sources.clone();
    composed.toolfs = toolfs.0;
    let signed = composed.sign(&seed).unwrap();
    let closure = Store::open(root.join("closures"))
        .unwrap()
        .put(&serde_json::to_vec(&signed).unwrap())
        .unwrap();
    fs::write(
        root.join("trusted-closures.json"),
        json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[publisher],"revoked":[]})
            .to_string(),
    )
    .unwrap();
    let schema = Store::open(root.join("tool-schemas"))
        .unwrap()
        .put(br#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#)
        .unwrap();
    let mut materials = Vec::new();
    let mut bindings = Vec::new();
    for ((name, limits), source) in tools.iter().zip(&sources[1..]) {
        let entry = format!("/{name}");
        let hash = Hash::of(entry.as_bytes()).0;
        materials.push(
            json!({"name":name,"spec":{"revision":"v1","description":name,
            "supportOwner":"fixture","publisherKey":publisher,"executable":{"hash":hash},
            "closure":{"hash":source.hash},"entryPoint":entry,"invocationABI":"celln.json-stdio/v1",
            "argumentsSchema":{"hash":schema.0},"resultSchema":{"hash":schema.0},
            "platform":"linux/amd64","lane":"tool","limits":limits}}),
        );
        bindings.push(json!({"name":name,"revision":"v1","hash":hash,"limits":limits}));
    }
    let store = Store::open(root.join("tool-schemas")).unwrap();
    let input = store
        .put(br#"{"type":"object","properties":{"text":{"type":"string","minLength":0,"maxLength":64}},"required":["text"],"additionalProperties":false}"#)
        .unwrap();
    let output = store
        .put(
            pilot::json_harness::argv_output_schema()
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let plain = limits("none", Value::Null, Value::Null);
    for (name, source) in commands.iter().zip(&sources[1 + tools.len()..]) {
        let entry = format!("/{name}");
        let hash = Hash::of(entry.as_bytes()).0;
        crate::tool_argv::publish(
            root,
            &crate::tool_argv::Identity {
                path: &entry,
                hash: &hash,
                input_schema: &input.0,
                output_schema: &output.0,
            },
            &pilot::json_harness::Argv {
                args: vec![(*name).into(), "{text}".into()],
                stdin: None,
            },
        )
        .unwrap();
        materials.push(
            json!({"name":name,"spec":{"revision":"v1","description":name,
            "supportOwner":"fixture","publisherKey":publisher,"executable":{"hash":hash},
            "closure":{"hash":source.hash},"entryPoint":entry,"invocationABI":"celln.argv/v1",
            "argumentsSchema":{"hash":input.0},"resultSchema":{"hash":output.0},
            "platform":"linux/amd64","lane":"tool","limits":plain}}),
        );
        bindings.push(json!({"name":name,"revision":"v1","hash":hash,"limits":plain}));
    }
    (
        Artifacts {
            mote: Hash::of(b"scoped-toolbox-mote").0,
            executable: Hash::of(b"/harness").0,
            closure: closure.0,
            publisher,
            entry_point: "/harness".into(),
        },
        materials,
        bindings,
    )
}

fn limits(effects: &str, artifacts: Value, https: Value) -> Value {
    json!({"timeoutMillis":30000,"memoryBytes":268435456,"argumentBytes":8192,"outputBytes":32768,
        "workspace":"none","effects":effects,"artifacts":artifacts,"https":https})
}

/// The fleet starter toolbox's own signed limits.
fn starter() -> Vec<(&'static str, Value)> {
    let web =
        json!({"allowHosts":["*"],"maxRequests":4,"maxResponseBytes":4096,"timeoutMillis":10000});
    let data = |operation: &str| json!({"operation":operation,"maxOperations":8,"maxFiles":8,"maxFileBytes":4096,"maxTotalBytes":16384});
    let mut tools = vec![
        (
            "https-fetch",
            limits("external-side-effects", Value::Null, web.clone()),
        ),
        (
            "https-post-json",
            limits("external-side-effects", Value::Null, web),
        ),
    ];
    for (name, operation, effects) in [
        ("workspace-read", "read", "none"),
        ("workspace-write", "write", "external-side-effects"),
        ("workspace-list", "list", "none"),
        ("workspace-append", "append", "external-side-effects"),
        ("workspace-search", "search", "none"),
        ("workspace-delete", "delete", "external-side-effects"),
    ] {
        tools.push((name, limits(effects, data(operation), Value::Null)));
    }
    tools
}

fn with_tools(
    operation: &mut Value,
    decision: &mut Value,
    materials: Vec<Value>,
    bindings: Vec<Value>,
) {
    operation["resolution"]["execution"]["tools"] = json!(materials);
    decision["tools"] = json!(bindings);
    operation["resolution"]["decision"] = decision.clone();
}

#[test]
fn a_one_shot_mediated_run_gets_the_starter_toolbox_behind_the_fleet_broker() {
    let root = tempfile::tempdir().unwrap();
    let (artifacts, materials, bindings) = toolbox(root.path(), &starter());
    let gateway = Gateway::serve(root.path(), vec!["CELLN".into()]);
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 1,
            gateway: Some((&gateway.origin, &gateway.ca)),
            parent_template: None,
        },
    );
    let scoped = state.scoped.as_ref().unwrap();
    let (mut operation, mut decision) =
        compose(&artifacts, one_shot("toolbox-run", true, unix_now()));
    with_tools(&mut operation, &mut decision, materials, bindings);
    let (id, _) = prepare(&state, &operation, &decision);
    let prepared = scoped.load_prepared(&id).unwrap();
    let execution = Permit::execution(&decision, "toolbox-execution").sign(&decision);
    let model = Permit::model(&decision, "toolbox-model").sign(&decision);
    let receiver = receiver_context(&operation, &decision, "execution.start").unwrap();
    let control = operation_control(&prepared).unwrap();
    let (native, broker) = build_native(
        scoped,
        &prepared,
        &receiver,
        &execution,
        Some(&model),
        &control,
    )
    .unwrap();
    // Broker authority only: no standing egress or runtime workspace.
    assert!(native.capabilities.egress.is_empty());
    assert_eq!(
        native.capabilities.workspace,
        celln_spec::WorkspaceAccess::None
    );
    let mut broker = broker.unwrap();
    assert!(broker.is_mediated());
    let data = |body: Value| json!({"apiVersion":"celln.workspace/v1","body":body}).to_string();
    let reply = |broker: &mut HttpBroker, body: Value| -> Option<Value> {
        broker
            .fetch(&data(body))
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    };
    // All six workspace operations, in the run's own private store.
    assert_eq!(
        reply(
            &mut broker,
            json!({"operation":"write","name":"notes.txt","revision":0,"content":"violet\n"})
        ),
        Some(json!({"revision":1}))
    );
    assert_eq!(
        reply(
            &mut broker,
            json!({"operation":"append","name":"notes.txt","revision":1,"content":"red\n"})
        ),
        Some(json!({"revision":2}))
    );
    assert_eq!(
        reply(&mut broker, json!({"operation":"read","name":"notes.txt"})),
        Some(json!({"revision":2,"content":"violet\nred\n"}))
    );
    assert_eq!(
        reply(&mut broker, json!({"operation":"list"})),
        Some(json!({"revision":2,"files":[{"name":"notes.txt","bytes":11}]}))
    );
    assert_eq!(
        reply(&mut broker, json!({"operation":"search","pattern":"red"})),
        Some(json!({"revision":2,"matches":[{"name":"notes.txt","line":2,"text":"red"}]}))
    );
    assert_eq!(
        reply(
            &mut broker,
            json!({"operation":"delete","name":"notes.txt","revision":2})
        ),
        Some(json!({"revision":3}))
    );
    assert_eq!(
        reply(
            &mut broker,
            json!({"operation":"read","name":"../etc/passwd"})
        ),
        None
    );
    // Web tools: the fleet's public-only enforcement, before any I/O.
    let post = |url: &str| {
        json!({"apiVersion":"celln.fetch/v1","method":"POST","url":url,"body":{"event":"done"}})
            .to_string()
    };
    for url in [
        "https://10.0.0.1/",
        "https://127.0.0.1/",
        "https://169.254.169.254/latest/meta-data/",
    ] {
        assert_eq!(
            broker.fetch(url).unwrap_err(),
            warden::egress::FetchDenied::Address,
            "{url}"
        );
        assert_eq!(
            broker.fetch(&post(url)).unwrap_err(),
            warden::egress::FetchDenied::Address,
            "{url}"
        );
    }
    assert_eq!(
        broker.fetch("http://example.com/").unwrap_err(),
        warden::egress::FetchDenied::Scheme
    );
    assert_eq!(
        broker.fetch("https://example.com:8443/").unwrap_err(),
        warden::egress::FetchDenied::Authority
    );
    // The gateway saw nothing from any of that; the model alias still works.
    assert!(gateway.seen().is_empty());
    let route_model = decision["route"]["model"].as_str().unwrap();
    let chat = json!({"apiVersion":"celln.fetch/v1","method":"POST","url":MODEL_ALIAS,
        "body":{"model":route_model,"stream":false,"max_tokens":64,
            "messages":[{"role":"user","content":"Reply with CELLN."}]}})
    .to_string();
    assert!(String::from_utf8(broker.fetch(&chat).unwrap())
        .unwrap()
        .contains("CELLN"));
    assert_eq!(gateway.seen().len(), 1);
}

#[test]
fn web_tool_limits_are_bounded_by_the_signed_decision_at_prepare() {
    let root = tempfile::tempdir().unwrap();
    let tools = starter();
    let (artifacts, materials, bindings) = toolbox(root.path(), &tools[..1]);
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 1,
            egress_slots: 1,
            gateway: None,
            parent_template: None,
        },
    );
    for (pointer, value, status) in [
        ("/allowHosts", json!(["*"]), 200),
        ("/maxRequests", json!(5), 422),
        ("/allowHosts", json!(["*", "docs.example.com"]), 422),
        ("/timeoutMillis", json!(30001), 422),
    ] {
        let (mut operation, mut decision) =
            compose(&artifacts, one_shot("limits-run", true, unix_now()));
        let mut bindings = bindings.clone();
        *bindings[0]["limits"]["https"].pointer_mut(pointer).unwrap() = value;
        with_tools(&mut operation, &mut decision, materials.clone(), bindings);
        let (code, _) = post(
            &state,
            "prepare",
            Headers::operator(),
            &json!({"operation":operation,"decision":decision}),
        );
        assert_eq!(code, status, "{pointer}");
    }
}

#[test]
fn an_enduring_broker_gets_web_tools_only_per_reserved_turn() {
    let root = tempfile::tempdir().unwrap();
    let (artifacts, materials, bindings) = toolbox(root.path(), &starter()[..2]);
    let gateway = Gateway::serve(root.path(), vec![]);
    let state = node(
        root.path(),
        NodeOptions {
            max_cells: 2,
            egress_slots: 1,
            gateway: Some((&gateway.origin, &gateway.ca)),
            parent_template: None,
        },
    );
    let scoped = state.scoped.as_ref().unwrap();
    let (mut operation, mut decision) = compose(
        &artifacts,
        enduring("enduring-tools", None, true, unix_now()),
    );
    with_tools(&mut operation, &mut decision, materials, bindings);
    let (id, _) = prepare(&state, &operation, &decision);
    let prepared = scoped.load_prepared(&id).unwrap();
    let execution = Permit::execution(&decision, "enduring-execution").sign(&decision);
    let model = Permit::model(&decision, "enduring-model").sign(&decision);
    let receiver = receiver_context(&operation, &decision, "execution.start").unwrap();
    let control = operation_control(&prepared).unwrap();
    let (_, broker) = build_native(
        scoped,
        &prepared,
        &receiver,
        &execution,
        Some(&model),
        &control,
    )
    .unwrap();
    let broker = broker.unwrap();
    // The pending turn's transport is still model-only, so the worker's
    // reserved-turn check passes; the web grants are attached after it.
    assert!(broker.fits_mediated_turn(64, 1 << 20));
    let policy = super::https::derive(&operation["resolution"]["execution"], &decision)
        .unwrap()
        .unwrap();
    let (get, post) = policy.grants(Duration::from_secs(60));
    let mut attached = broker.with_scoped_https(get, post).unwrap();
    assert!(!attached.fits_mediated_turn(64, 1 << 20));
    assert_eq!(
        attached.fetch("https://192.168.0.1/").unwrap_err(),
        warden::egress::FetchDenied::Address
    );
}

/// The fleet's borrowed commands, as the starter package lends them.
const COMMANDS: [&str; 14] = [
    "cat", "echo", "grep", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "sed", "date",
    "base64", "jq",
];

/// Prepares a one-shot mediated run lending exactly these tools and builds its
/// native request, as the start route does.
fn build_lending(
    run: &str,
    root: &Path,
    artifacts: &Artifacts,
    materials: Vec<Value>,
    bindings: Vec<Value>,
) -> Result<ExecutionRequest, String> {
    let gateway = Gateway::serve(root, vec![]);
    let state = node(
        root,
        NodeOptions {
            max_cells: 1,
            egress_slots: 1,
            gateway: Some((&gateway.origin, &gateway.ca)),
            parent_template: None,
        },
    );
    let scoped = state.scoped.as_ref().unwrap();
    let (mut operation, mut decision) = compose(artifacts, one_shot(run, true, unix_now()));
    with_tools(&mut operation, &mut decision, materials, bindings);
    let (code, _) = post(
        &state,
        "prepare",
        Headers::operator(),
        &json!({"operation":operation,"decision":decision}),
    );
    assert_eq!(code, 200, "the prepare route admits the selection");
    let (id, _) = prepare(&state, &operation, &decision);
    let prepared = scoped.load_prepared(&id).unwrap();
    let execution = Permit::execution(&decision, "toolbox-closure-execution").sign(&decision);
    let model = Permit::model(&decision, "toolbox-closure-model").sign(&decision);
    let receiver = receiver_context(&operation, &decision, "execution.start").unwrap();
    let control = operation_control(&prepared).unwrap();
    build_native(
        scoped,
        &prepared,
        &receiver,
        &execution,
        Some(&model),
        &control,
    )
    .map(|(native, _)| native)
}

#[test]
fn the_whole_starter_toolbox_runs_on_its_toolbox_closure() {
    let root = tempfile::tempdir().unwrap();
    let (artifacts, materials, bindings) = toolbox_lending(root.path(), &starter(), &COMMANDS);
    assert_eq!(materials.len(), 22);
    let native = build_lending("toolbox-full", root.path(), &artifacts, materials, bindings)
        .ok()
        .unwrap();
    let config: pilot::json_harness::Config =
        serde_json::from_str(&native.invocation.as_ref().unwrap().args[0]).unwrap();
    pilot::json_harness::validate(&config).unwrap();
    let paths: Vec<_> = config.tools.iter().map(|tool| tool.path.as_str()).collect();
    let expected: Vec<_> = starter()
        .iter()
        .map(|(name, _)| format!("/{name}"))
        .chain(COMMANDS.iter().map(|name| format!("/{name}")))
        .collect();
    assert_eq!(paths, expected);
    // A borrowed command carries this node's reviewed binding; a brokered
    // tool none.
    for tool in &config.tools {
        let name = tool.path.trim_start_matches('/');
        match COMMANDS.contains(&name) {
            true => assert_eq!(
                tool.argv,
                Some(pilot::json_harness::Argv {
                    args: vec![name.into(), "{text}".into()],
                    stdin: None
                })
            ),
            false => assert!(tool.argv.is_none()),
        }
    }
}

#[test]
fn a_partial_or_reordered_selection_of_the_toolbox_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let (artifacts, materials, bindings) = toolbox_lending(root.path(), &starter(), &COMMANDS);
    // One tool fewer: the cell would carry an unselected executable.
    let mut fewer = (materials.clone(), bindings.clone());
    fewer.0.pop();
    fewer.1.pop();
    assert_eq!(
        build_lending("toolbox-fewer", root.path(), &artifacts, fewer.0, fewer.1)
            .err()
            .unwrap(),
        "prepared closure source count mismatch"
    );
    // Every tool, in another order: each must be the closure's source at
    // its own position.
    let mut reordered = (materials.clone(), bindings.clone());
    reordered.0.swap(0, 21);
    reordered.1.swap(0, 21);
    assert_eq!(
        build_lending(
            "toolbox-reordered",
            root.path(),
            &artifacts,
            reordered.0,
            reordered.1
        )
        .err()
        .unwrap(),
        "prepared tool closure mismatch"
    );
}

#[test]
fn a_borrowed_command_without_a_reviewed_binding_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let (artifacts, materials, bindings) = toolbox_lending(root.path(), &[], &["cat"]);
    fs::remove_dir_all(root.path().join("tool-argv")).unwrap();
    assert_eq!(
        build_lending("unreviewed", root.path(), &artifacts, materials, bindings)
            .err()
            .unwrap(),
        "AUTH_PROTOCOL_UNSUPPORTED"
    );
}
