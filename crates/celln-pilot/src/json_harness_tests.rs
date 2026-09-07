use super::*;
use std::cell::Cell;

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
