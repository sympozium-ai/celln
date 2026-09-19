use super::*;
use std::cell::Cell;

#[test]
fn parent_history_maps_to_roles_without_replacing_host_persona() {
    let cfg = config(&[]);
    let history = [Exchange {
        user: "my value is violet".into(),
        assistant: "recorded".into(),
    }];
    run_with_history(
        &cfg,
        &history,
        |wire| {
            let wire: Value = serde_json::from_slice(wire)?;
            assert_eq!(
                wire["body"]["messages"],
                json!([
                    {"role":"system", "content":cfg.system},
                    {"role":"user", "content":"my value is violet"},
                    {"role":"assistant", "content":"recorded"},
                    {"role":"user", "content":cfg.task}
                ])
            );
            Ok(answer())
        },
        |_, _| panic!("no tools requested"),
        |_| {},
    )
    .unwrap();
}

#[test]
fn invalid_or_oversized_context_never_reaches_model() {
    let cfg = config(&[]);
    for history in [
        vec![Exchange {
            user: "x".repeat(warden::parent_protocol::MAX_TASK_BYTES),
            assistant: "y".into(),
        }],
        vec![Exchange {
            user: "x\0".into(),
            assistant: "y".into(),
        }],
        vec![
            Exchange {
                user: "x".into(),
                assistant: "y".into()
            };
            17
        ],
    ] {
        assert!(run_with_history(
            &cfg,
            &history,
            |_| panic!("must refuse before model"),
            |_, _| panic!("must refuse before tool"),
            |_| {}
        )
        .is_err());
    }
    assert!(serde_json::from_value::<Exchange>(
        json!({"user":"x", "assistant":"y", "system":"override"})
    )
    .is_err());
}

fn schema(bytes: &str) -> Schema {
    Schema {
        bytes: bytes.into(),
        hash: Hash::of(bytes.as_bytes()).0,
    }
}
fn config(names: &[&str]) -> Config {
    let object = r#"{"type":"object","properties":{"text":{"type":"string","minLength":1,"maxLength":64}},"required":["text"],"additionalProperties":false}"#;
    Config {
        contract: CONTRACT.into(),
        task: "use structured text tools".into(),
        system: "Bounded agent".into(),
        url: "https://api.deepseek.com/chat/completions".into(),
        model: "deepseek-chat".into(),
        max_turns: 6,
        max_calls: 6,
        require_tool_call: false,
        allow_insecure: false,
        tools: names
            .iter()
            .map(|name| Tool {
                name: (*name).into(),
                path: format!("/{name}"),
                hash: Hash::of(name.as_bytes()).0,
                description: "Returns structured text".into(),
                input_schema: schema(object),
                output_schema: schema(object),
                input_bytes: 1024,
                output_bytes: 1024,
                timeout_ms: 1000,
                argv: None,
            })
            .collect(),
    }
}
fn call(id: &str, name: &str, args: &str) -> Value {
    json!({"id":id,"type":"function","function":{"name":name,"arguments":args}})
}
fn response(calls: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":calls}}]}),
    )
    .unwrap()
}
fn answer() -> Vec<u8> {
    serde_json::to_vec(&json!({"choices":[{"message":{"role":"assistant","content":"completed structured task"}}]})).unwrap()
}

#[test]
fn required_tool_call_is_requested_and_locally_enforced_without_retry() {
    let mut cfg = config(&["echo"]);
    cfg.require_tool_call = true;
    let mut events = Vec::new();
    let mut requests = 0;
    assert!(run(
        &cfg,
        |wire| {
            requests += 1;
            let wire: Value = serde_json::from_slice(wire).unwrap();
            assert_eq!(wire["body"]["tool_choice"], "required");
            Ok(answer())
        },
        |_, _| panic!("invented execution"),
        |e| events.push(e)
    )
    .is_err());
    assert_eq!(requests, 1);
    assert!(!events.iter().any(|e| e["type"] == "completed"));
    requests = 0;
    let result = run(
        &cfg,
        |wire| {
            requests += 1;
            let wire: Value = serde_json::from_slice(wire).unwrap();
            if requests == 1 {
                assert_eq!(wire["body"]["tool_choice"], "required");
                Ok(response(vec![call("one", "echo", r#"{"text":"hello"}"#)]))
            } else {
                assert_eq!(wire["body"]["tool_choice"], "auto");
                Ok(answer())
            }
        },
        |_, input| Ok(input.to_vec()),
        |_| {},
    )
    .unwrap();
    assert_eq!(result, "completed structured task");
    assert_eq!(requests, 2);
}

#[test]
fn required_tool_call_refuses_impossible_budgets_and_preserves_old_templates() {
    let original = config(&["echo"]);
    let raw = serde_json::to_value(&original).unwrap();
    assert!(raw.get("require_tool_call").is_none());
    let restored: Config = serde_json::from_value(raw.clone()).unwrap();
    assert!(!restored.require_tool_call);
    assert_eq!(serde_json::to_value(restored).unwrap(), raw);
    let mut optional = original.clone();
    optional.task.clear();
    let mut required = optional.clone();
    required.require_tool_call = true;
    assert_ne!(
        crate::turn_worker::Template::new(optional)
            .unwrap()
            .binding(),
        crate::turn_worker::Template::new(required)
            .unwrap()
            .binding()
    );
    let mut required = original.clone();
    required.require_tool_call = true;
    assert!(run(
        &required,
        |_| Ok(response(vec![call(
            "one",
            "not-lent",
            r#"{"text":"hello"}"#
        )])),
        |_, _| panic!("required policy expanded tool authority"),
        |_| {}
    )
    .is_err());
    for mode in 0..3 {
        let mut cfg = original.clone();
        cfg.require_tool_call = true;
        match mode {
            0 => cfg.tools.clear(),
            1 => cfg.max_calls = 0,
            _ => cfg.max_turns = 1,
        }
        assert!(run(
            &cfg,
            |_| panic!("invalid policy reached broker"),
            |_, _| panic!("invalid policy executed"),
            |_| {}
        )
        .is_err());
    }
}

#[test]
fn structured_tools_need_not_all_be_used_and_results_return_to_model() {
    let cfg = config(&["echo", "second", "unused"]);
    let count = Cell::new(0);
    let mut events = Vec::new();
    let result = run(
        &cfg,
        |wire| {
            let wire: Value = serde_json::from_slice(wire).unwrap();
            assert_eq!(wire["body"]["tool_choice"], "auto");
            count.set(count.get() + 1);
            match count.get() {
                1 => Ok(response(vec![
                    call(
                        "one",
                        "echo",
                        r#"{"text":"borrowed strings, not integers"}"#,
                    ),
                    call("two", "second", r#"{"text":"second"}"#),
                ])),
                2 => {
                    let messages = wire["body"]["messages"].as_array().unwrap();
                    assert_eq!(messages.iter().filter(|m| m["role"] == "tool").count(), 2);
                    assert!(messages
                        .iter()
                        .any(|m| m["content"] == r#"{"text":"borrowed strings, not integers"}"#));
                    Ok(answer())
                }
                _ => panic!("unexpected broker call"),
            }
        },
        |_, input| Ok(input.to_vec()),
        |e| events.push(e),
    )
    .unwrap();
    assert_eq!(result, "completed structured task");
    assert_eq!(events.iter().filter(|e| e["type"] == "tool").count(), 2);
}

#[test]
fn empty_selection_has_no_tools_and_can_complete_without_calls() {
    let cfg = config(&[]);
    run(
        &cfg,
        |wire| {
            let wire: Value = serde_json::from_slice(wire).unwrap();
            assert!(wire["body"].get("tools").is_none());
            Ok(answer())
        },
        |_, _| panic!("no borrowed authority"),
        |_| {},
    )
    .unwrap();
}

#[test]
fn invalid_batches_never_execute_even_the_first_valid_member() {
    for bad in [
        call("two", "unselected", r#"{"text":"x"}"#),
        call("one", "echo", r#"{"text":"x"}"#),
        call("two", "echo", r#"{"text":"x","text":"duplicate"}"#),
        call("two", "echo", r#"{"text":42}"#),
        call("two", "echo", r#"{"text":"x","extra":true}"#),
    ] {
        let cfg = config(&["echo"]);
        let bytes = response(vec![call("one", "echo", r#"{"text":"valid"}"#), bad]);
        assert!(run(
            &cfg,
            |_| Ok(bytes.clone()),
            |_, _| panic!("invalid batch executed"),
            |_| {}
        )
        .is_err());
    }
}

#[test]
fn schema_identity_and_output_validation_are_authoritative() {
    let mut cfg = config(&["echo"]);
    cfg.tools[0].input_schema.bytes.push(' ');
    assert!(run(
        &cfg,
        |_| panic!("invalid schema reached broker"),
        |_, _| panic!(),
        |_| {}
    )
    .is_err());
    let cfg = config(&["echo"]);
    let calls = Cell::new(0);
    assert!(run(
        &cfg,
        |_| {
            calls.set(calls.get() + 1);
            Ok(response(vec![call("one", "echo", r#"{"text":"x"}"#)]))
        },
        |_, _| Ok(br#"{"unexpected":true}"#.to_vec()),
        |_| {}
    )
    .is_err());
    assert_eq!(
        calls.get(),
        1,
        "invalid output must not feed another model call"
    );
}

#[test]
fn budgets_and_repeated_call_ids_stop_the_loop() {
    let mut cfg = config(&["echo"]);
    cfg.max_calls = 0;
    assert!(run(
        &cfg,
        |_| Ok(response(vec![call("one", "echo", r#"{"text":"x"}"#)])),
        |_, _| panic!(),
        |_| {}
    )
    .is_err());
    cfg.max_calls = 6;
    let executes = Cell::new(0);
    assert!(run(
        &cfg,
        |_| Ok(response(vec![call("repeated", "echo", r#"{"text":"x"}"#)])),
        |_, input| {
            executes.set(executes.get() + 1);
            Ok(input.to_vec())
        },
        |_| {}
    )
    .is_err());
    assert_eq!(executes.get(), 1);
}

#[test]
fn final_model_turn_cannot_start_side_effects_without_a_result_turn() {
    let mut cfg = config(&["echo"]);
    cfg.max_turns = 1;
    let executes = Cell::new(0);
    let error = run(
        &cfg,
        |_| Ok(response(vec![call("one", "echo", r#"{"text":"x"}"#)])),
        |_, input| {
            executes.set(executes.get() + 1);
            Ok(input.to_vec())
        },
        |_| {},
    )
    .unwrap_err();
    assert_eq!(executes.get(), 0, "no turn remains to consume tool results");
    assert!(error.to_string().contains("result turn"));
    // The same last-turn budget must still permit a tool-free final answer.
    assert!(run(&cfg, |_| Ok(answer()), |_, _| panic!(), |_| {}).is_ok());
}

#[test]
fn host_validation_rejects_initial_envelope_overflow_before_execution() {
    let names: Vec<_> = (0..24).map(|n| format!("tool{n}")).collect();
    let refs: Vec<_> = names.iter().map(String::as_str).collect();
    let mut cfg = config(&refs);
    // Two dozen tools with the longest allowed descriptions and wide (but
    // valid) argument schemas overflow the model wire budget.
    let wide = {
        let properties: serde_json::Map<String, Value> = (0..32)
            .map(|i| {
                (
                    format!("field{i}{}", "y".repeat(56)),
                    json!({"type":"string","minLength":0,"maxLength":64}),
                )
            })
            .collect();
        json!({"type":"object","properties":properties,"required":[],"additionalProperties":false})
            .to_string()
    };
    for tool in &mut cfg.tools {
        tool.description = "x".repeat(512);
        tool.input_schema = schema(&wide);
    }
    assert!(validate(&cfg).unwrap_err().to_string().contains("envelope"));
    assert!(run(
        &cfg,
        |_| panic!("must refuse before broker"),
        |_, _| panic!(),
        |_| {}
    )
    .is_err());
    // The same two dozen tools, plainly described, fit.
    let mut cfg = config(&refs);
    for tool in &mut cfg.tools {
        tool.description = "x".repeat(160);
    }
    assert!(validate(&cfg).is_ok());
}

// A borrowed command: validated JSON becomes argv/stdin through the fixed
// binding, never a shell; its stdout and exit status come back as data.
#[test]
fn argv_binding_maps_validated_arguments_and_reports_exit_status() {
    let output_bytes = 4096;
    let input = r#"{"type":"object","properties":{"pattern":{"type":"string","minLength":1,"maxLength":64},"text":{"type":"string","minLength":0,"maxLength":1024},"ignore_case":{"type":"boolean"},"count":{"type":"integer","minimum":0,"maximum":9}},"required":["pattern","text"],"additionalProperties":false}"#;
    let mut tool = Tool {
        name: "grep".into(),
        path: "/busybox".into(),
        hash: format!("blake3:{}", "a".repeat(64)),
        description: "grep".into(),
        input_schema: schema(input),
        output_schema: schema(&argv_output_schema().to_string()),
        input_bytes: 2048,
        output_bytes,
        timeout_ms: 1000,
        argv: Some(Argv {
            args: vec![
                "grep".into(),
                "{ignore_case?-i}".into(),
                "{count:-m}".into(),
                "-e".into(),
                "{pattern}".into(),
            ],
            stdin: Some("text".into()),
        }),
    };
    let mut cfg = config(&[]);
    cfg.tools = vec![tool.clone()];
    cfg.max_calls = 1;
    cfg.max_turns = 2;
    validate(&cfg).unwrap();
    let (args, stdin) = argv_invocation(
        &tool,
        br#"{"pattern":"vio","text":"violet\norange\n","ignore_case":true,"count":2}"#,
    )
    .unwrap();
    assert_eq!(args, ["grep", "-i", "-m", "2", "-e", "vio"]);
    assert_eq!(stdin, b"violet\norange\n");
    let (args, _) = argv_invocation(&tool, br#"{"pattern":"vio","text":""}"#).unwrap();
    assert_eq!(
        args,
        ["grep", "-e", "vio"],
        "absent optional fields drop their entries, flag included"
    );
    assert!(argv_invocation(&tool, br#"{"pattern":"a b","text":""}"#).is_err());
    let result: Value = serde_json::from_slice(&argv_output(1, b"")).unwrap();
    assert_eq!(result, json!({"output":"","exit":1}));
    let long: Value = serde_json::from_slice(&argv_output(0, "é".repeat(5000).as_bytes())).unwrap();
    assert!(long["output"].as_str().unwrap().len() <= ARGV_OUTPUT_CHARS);
    assert!(long["output"].as_str().unwrap().starts_with("éé"));
    // The binding is checked against the schema it is declared with.
    tool.argv = Some(Argv {
        args: vec!["{missing}".into()],
        stdin: None,
    });
    cfg.tools = vec![tool.clone()];
    assert!(validate(&cfg).is_err());
    tool.argv = Some(Argv {
        args: vec!["{pattern?-x}".into()],
        stdin: None,
    });
    cfg.tools = vec![tool.clone()];
    assert!(
        validate(&cfg).is_err(),
        "a flag placeholder needs a boolean field"
    );
    tool.argv = Some(Argv {
        args: vec!["grep".into()],
        stdin: Some("count".into()),
    });
    cfg.tools = vec![tool.clone()];
    assert!(validate(&cfg).is_err(), "stdin needs a string field");
    tool.argv = Some(Argv {
        args: vec!["grep".into()],
        stdin: None,
    });
    tool.output_schema =
        schema(r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#);
    cfg.tools = vec![tool];
    assert!(
        validate(&cfg).is_err(),
        "argv tools return the argv result shape"
    );
}

fn reply(content: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"choices":[{"message":{"role":"assistant","content":content}}]}))
        .unwrap()
}

#[test]
fn final_answers_are_bounded_at_eight_kibibytes_and_state_their_limit() {
    assert_eq!(MAX_ANSWER_BYTES, 8192);
    let cfg = config(&[]);
    let mut events = Vec::new();
    let full = "a".repeat(MAX_ANSWER_BYTES);
    assert_eq!(
        run(
            &cfg,
            |_| Ok(reply(&full)),
            |_, _| panic!(),
            |e| events.push(e)
        )
        .unwrap(),
        full
    );
    let completed = events.iter().find(|e| e["type"] == "completed").unwrap();
    assert_eq!(completed["answerLimit"], 8192);
    // One byte more, or nothing at all, fails the turn with its own reason.
    let over = "a".repeat(MAX_ANSWER_BYTES + 1);
    let error = run(&cfg, |_| Ok(reply(&over)), |_, _| panic!(), |_| {}).unwrap_err();
    assert!(error
        .to_string()
        .contains("final answer exceeds 8192 bytes"));
    let error = run(&cfg, |_| Ok(reply(" ")), |_, _| panic!(), |_| {}).unwrap_err();
    assert_eq!(error.to_string(), "final answer is empty");
}

#[test]
fn a_long_history_gives_way_to_tool_rounds_oldest_exchange_first() {
    let history: Vec<_> = (0..8)
        .map(|i| Exchange {
            user: format!("question {i}"),
            assistant: "a".repeat(2000),
        })
        .collect();
    let sent = |cfg: &Config| {
        let (mut users, mut events, mut length) = (Vec::new(), Vec::new(), 0usize);
        run_with_history(
            cfg,
            &history,
            |wire| {
                let value: Value = serde_json::from_slice(wire)?;
                users = value["body"]["messages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|m| m["role"] == "user")
                    .map(|m| m["content"].as_str().unwrap().to_owned())
                    .collect();
                length = wire.len();
                Ok(answer())
            },
            |_, _| panic!("no tool requested"),
            |event| events.push(event),
        )
        .unwrap();
        (users, events, length)
    };
    // Without tools there are no later rounds: the whole history is sent.
    let (users, events, _) = sent(&config(&[]));
    assert_eq!(users.len(), history.len() + 1);
    assert!(events.iter().all(|e| e["type"] != "context"));
    // With tools the first request leaves the reserve free: the oldest
    // exchanges are left out, the newest and the task stay, and it is said.
    let cfg = config(&["echo"]);
    let (users, events, wire) = sent(&cfg);
    assert!(users.len() > 2 && users.len() < history.len() + 1);
    assert_eq!(users[users.len() - 1], cfg.task);
    assert_eq!(users[users.len() - 2], "question 7");
    assert!(wire <= MODEL_WIRE_BYTES - TOOL_ROUND_WIRE_RESERVE);
    let context = events.iter().find(|e| e["type"] == "context").unwrap();
    assert_eq!(context["historyKept"], users.len() as u64 - 1);
    assert_eq!(
        context["historyDropped"],
        (history.len() + 1 - users.len()) as u64
    );
    // Host validation of the same turn agrees instead of refusing it.
    assert!(validate_with_history(&cfg, &history).is_ok());
}

fn finished(message: Value, finish: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"choices":[{"index":0,"message":message,"finish_reason":finish}]}))
        .unwrap()
}

fn outcome(response: Vec<u8>) -> Result<String> {
    run(
        &config(&[]),
        |_| Ok(response.clone()),
        |_, _| panic!("no tools requested"),
        |_| {},
    )
}

#[test]
fn an_answer_starved_by_reasoning_is_diagnosed_as_such() {
    // llama-server with a thinking model: every token went to reasoning.
    for content in [json!(""), json!("  \n"), Value::Null] {
        let error = outcome(finished(
            json!({"role":"assistant","content":content,"reasoning_content":"Let me think..."}),
            "length",
        ))
        .unwrap_err()
        .to_string();
        assert_eq!(error, EMPTY_AT_LENGTH);
        assert!(error.starts_with("final answer is empty"));
        assert!(error.contains("512 tokens") && error.contains("disable thinking"));
        // The reasoning text is never quoted into the error.
        assert!(!error.contains("Let me think"));
    }
    // No content field at all, as the Anthropic normalisation cannot produce
    // but an OpenAI-compatible server may.
    assert_eq!(
        outcome(finished(json!({"role":"assistant"}), "length"))
            .unwrap_err()
            .to_string(),
        EMPTY_AT_LENGTH
    );
    // An empty answer that did not hit the ceiling keeps the plain message.
    assert_eq!(
        outcome(finished(json!({"role":"assistant","content":""}), "stop"))
            .unwrap_err()
            .to_string(),
        "final answer is empty"
    );
    // A truncated but present answer is still an answer.
    assert_eq!(
        outcome(finished(
            json!({"role":"assistant","content":"partial"}),
            "length"
        ))
        .unwrap(),
        "partial"
    );
}

#[test]
fn llama_server_shaped_responses_with_extra_fields_parse_as_before() {
    let response = serde_json::to_vec(&json!({
        "id":"chatcmpl-x","object":"chat.completion","created":1,"model":"qwen",
        "system_fingerprint":"b1-x",
        "choices":[{"index":0,"finish_reason":"stop","message":{
            "role":"assistant","content":"Paris.","reasoning_content":"The capital of France"}}],
        "usage":{"prompt_tokens":20,"completion_tokens":115,"total_tokens":135},
        "timings":{"prompt_n":20,"prompt_ms":31.5,"predicted_n":115,"predicted_per_second":48.2}
    }))
    .unwrap();
    let mut events = Vec::new();
    let answer = run(
        &config(&[]),
        |_| Ok(response.clone()),
        |_, _| panic!("no tools requested"),
        |event| events.push(event),
    )
    .unwrap();
    assert_eq!(answer, "Paris.");
    // Reasoning is not part of the answer or of any event.
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains("capital of France"));
}
