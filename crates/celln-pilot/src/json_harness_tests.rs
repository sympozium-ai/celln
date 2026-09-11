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
            user: "x".repeat(4096),
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
    let names: Vec<_> = (0..16).map(|n| format!("tool{n}")).collect();
    let refs: Vec<_> = names.iter().map(String::as_str).collect();
    let mut cfg = config(&refs);
    for tool in &mut cfg.tools {
        tool.description = "x".repeat(512);
    }
    assert!(validate(&cfg).unwrap_err().to_string().contains("envelope"));
    assert!(run(
        &cfg,
        |_| panic!("must refuse before broker"),
        |_, _| panic!(),
        |_| {}
    )
    .is_err());
}
