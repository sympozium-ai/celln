//! Deterministic native proof, no external provider or standing model profile.
use super::*;

pub(crate) fn prove_scoped_artifacts_on_kvm(
    root: &Path,
    publisher: &str,
    parent: &ExecutionRequest,
    worker: &ExecutionRequest,
    tools: Value,
) {
    let call = |name: &str, arguments: Value| json!({"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":name,"arguments":arguments.to_string()}}]});
    let done = json!({"role":"assistant","content":"tool completed"});
    let gateway = Gateway::serve_messages(
        root,
        vec![
            call(
                "workspace-write",
                json!({"name":"notes/sentinel.txt","revision":0,"content":"artifact-violet"}),
            ),
            done.clone(),
            call("workspace-read", json!({"name":"notes/sentinel.txt"})),
            done.clone(),
            call("workspace-read", json!({"name":"notes/sentinel.txt"})),
            done,
        ],
    );
    let mut request = serde_json::to_value(parent).unwrap();
    request["id"] = json!("$parent");
    request["workload"] = json!({"id":"$parent","caller":"$principal"});
    let template = json!({"apiVersion":"celln.scoped-parent-template/v1","reservedMemoryBytes":1610612736u64,"request":request});
    let state = node(
        root,
        NodeOptions {
            max_cells: 2,
            egress_slots: 1,
            gateway: Some((&gateway.origin, &gateway.ca)),
            parent_template: Some(&template),
        },
    );
    let created = unix_now();
    let shape = Shape {
        parent_deadline: created + 600,
        ..enduring("kvm-artifact-run", None, true, created)
    };
    let artifacts = artifacts_of(worker, publisher);
    let mut statuses = Vec::new();
    let mut initial = None;
    let mut permits = Vec::new();
    for (index, turn) in [None, Some("artifact-turn-2"), Some("artifact-turn-3")]
        .into_iter()
        .enumerate()
    {
        let (mut operation, mut decision) = compose_requests(
            &artifacts,
            Shape {
                turn_id: turn,
                lifecycle: if turn.is_none() {
                    "enduring-initial"
                } else {
                    "enduring-turn"
                },
                issued: unix_now(),
                payload: "Perform the next approved artifact operation.",
                ..shape
            },
            Requests {
                per_turn: 2,
                budget: Some(((2, 1024), (6, 3072))),
                ..Requests::default()
            },
        );
        operation["resolution"]["execution"]["tools"] = tools.clone();
        operation["resolution"]["execution"]["profileSpec"]["json"]["maxCalls"] = json!(1);
        decision["tools"] = Value::Array(tools.as_array().unwrap().iter().map(|tool| {
            let mut limits = tool["spec"]["limits"].clone();
            limits["https"] = Value::Null;
            json!({"name":tool["name"],"revision":tool["spec"]["revision"],"hash":tool["spec"]["executable"]["hash"],"limits":limits})
        }).collect());
        let execution = &operation["resolution"]["execution"];
        decision["runtime"]["specSha256"] = json!(digest_value(&json!({"wrapperSpec":execution["wrapperSpec"],"profileName":execution["profileName"],"profileUid":execution["profileUid"],"profileDigest":digest_value(&execution["profileSpec"]).unwrap()})).unwrap());
        operation["resolution"]["decision"] = decision.clone();
        let (id, owner) = prepare(&state, &operation, &decision);
        let label = format!("artifact-execution-{index}");
        let execution = Permit::execution(&decision, &label).sign(&decision);
        let label = format!("artifact-model-{index}");
        let model = Permit::model(&decision, &label).sign(&decision);
        let (status, admitted) = post(
            &state,
            "start",
            Headers::permits(&execution, Some(&model)),
            &json!({"id":id,"owner":owner}),
        );
        assert_eq!(status, 202, "{admitted}");
        let (_, finished) = read_until(
            &state,
            &id,
            &decision,
            &format!("artifact-read-{index}"),
            &[
                "Running",
                "Succeeded",
                "Failed",
                "Refused",
                "Cancelled",
                "Uncertain",
            ],
        );
        assert_eq!(
            finished["phase"],
            if index == 0 { "Running" } else { "Succeeded" },
            "{finished}"
        );
        assert_eq!(finished["output"], "tool completed");
        assert_eq!(
            finished["parentIncarnation"],
            decision["parent"]["incarnation"]
        );
        assert!(finished["execution"].is_object() && finished["substrate"].is_object());
        assert!(!finished["cellId"].as_str().unwrap().is_empty());
        // Read actual tool output submitted by the guest, not the scripted
        // assistant's answer or retained conversation text.
        let seen = gateway.seen();
        assert_eq!(seen.len(), (index + 1) * 2);
        let message = seen.last().unwrap().1["request"]["messages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap();
        assert_eq!(message["role"], "tool");
        let output: Value = serde_json::from_str(message["content"].as_str().unwrap()).unwrap();
        assert_eq!(output["revision"], 1, "{output}");
        if index > 0 {
            assert_eq!(output["content"], "artifact-violet");
        }
        assert!(output.get("error").is_none());
        if index == 0 {
            initial = Some((id, decision));
        }
        statuses.push(finished);
        permits.extend([execution, model]);
    }
    let parent_id = &statuses[0]["parentId"];
    let mut children = std::collections::BTreeSet::new();
    let mut cells = std::collections::BTreeSet::new();
    for status in &statuses {
        assert_eq!(&status["parentId"], parent_id);
        children.insert(status["childId"].as_str().unwrap());
        cells.insert(status["cellId"].as_str().unwrap());
    }
    assert_eq!(children.len(), 3);
    assert_eq!(cells.len(), 3);
    assert_eq!(listed_parent(&state, parent_id)["turns_total"], 3);
    let (id, decision) = initial.unwrap();
    let cleanup_decision = access_decision(&decision, "execution.cleanup");
    let cleanup = Permit::access(&cleanup_decision, "artifact-cleanup").sign(&cleanup_decision);
    let (code, stopped) = post(
        &state,
        "cleanup",
        Headers::permits(&cleanup, None),
        &json!({"id":id,"decision":cleanup_decision}),
    );
    assert_eq!(code, 200, "{stopped}");
    assert_eq!(stopped["cleanupConfirmed"], true);
    assert_eq!(listed_parent(&state, parent_id)["status"], "Stopped");
    assert_eq!(gateway.seen().len(), 6);
    permits.push(cleanup);
    assert_never_stored(
        root,
        &permits.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    println!(
        "SCOPED_ARTIFACT_EVIDENCE {}",
        json!({"contract":"celln.scoped-artifacts/v1","turns":statuses,"cleanup":stopped,"modelRequests":6,"toolRepliesVerified":3,"installedAcceptance":false})
    );
}
