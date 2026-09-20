//! Operator-chosen provider request parameters for a model backend.
//!
//! Some backends need a field in the request itself (llama-server ignores
//! `--reasoning-budget 0` for some templates but honours
//! `chat_template_kwargs.enable_thinking`). The operator states such fields
//! once, at configure time; they are content-pinned in the model profile and
//! merged by the host broker after the guest request passed validation. The
//! guest neither sends nor sees them, and the fields Celln's own contract owns
//! are reserved so this door cannot change what the guest was granted.
use serde_json::{Map, Value};

pub const MAX_KEYS: usize = 16;
pub const MAX_DEPTH: usize = 3;
pub const MAX_STRING_BYTES: usize = 256;
pub const MAX_ARRAY_ITEMS: usize = 8;
pub const MAX_SERIALIZED_BYTES: usize = 2048;

/// Top-level provider fields owned by the broker contract (either protocol).
pub const RESERVED: [&str; 14] = [
    "model",
    "messages",
    "system",
    "stream",
    "stream_options",
    "max_tokens",
    "max_completion_tokens",
    "n",
    "tools",
    "tool_choice",
    "functions",
    "function_call",
    "parallel_tool_calls",
    "user",
];

fn valid_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

fn scalar(path: &str, value: &Value) -> Result<bool, String> {
    match value {
        Value::Bool(_) => Ok(true),
        Value::Number(number) => {
            if number.as_f64().is_some_and(f64::is_finite) {
                Ok(true)
            } else {
                Err(format!("model parameter {path} is not a finite number"))
            }
        }
        Value::String(text) => {
            if text.len() > MAX_STRING_BYTES || text.contains('\0') {
                Err(format!(
                    "model parameter {path} must be a string of at most {MAX_STRING_BYTES} bytes without NUL"
                ))
            } else {
                Ok(true)
            }
        }
        _ => Ok(false),
    }
}

fn object(path: &str, map: &Map<String, Value>, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "model parameter {path} nests deeper than {MAX_DEPTH} levels"
        ));
    }
    for (key, value) in map {
        let here = if path.is_empty() {
            key.clone()
        } else {
            format!("{path}.{key}")
        };
        if !valid_key(key) {
            // The key itself is untrusted operator text; name only its parent.
            let parent = if path.is_empty() {
                "the top level"
            } else {
                path
            };
            return Err(format!(
                "model parameter key under {parent} must match ^[a-z][a-z0-9_]{{0,63}}$"
            ));
        }
        if scalar(&here, value)? {
            continue;
        }
        match value {
            Value::Null => return Err(format!("model parameter {here} must not be null")),
            Value::Object(inner) => object(&here, inner, depth + 1)?,
            Value::Array(items) => {
                if items.len() > MAX_ARRAY_ITEMS {
                    return Err(format!(
                        "model parameter {here} has more than {MAX_ARRAY_ITEMS} array items"
                    ));
                }
                for item in items {
                    if !scalar(&here, item)? {
                        return Err(format!(
                            "model parameter {here} array items must be bool, number or string"
                        ));
                    }
                }
            }
            _ => unreachable!("scalars handled above"),
        }
    }
    Ok(())
}

/// The single rule set used when a plan is configured, when a pinned profile
/// is read back, and again by the broker before a request leaves the host.
pub fn validate(parameters: &Map<String, Value>) -> Result<(), String> {
    if parameters.len() > MAX_KEYS {
        return Err(format!(
            "model parameters allow at most {MAX_KEYS} top-level keys"
        ));
    }
    if let Some(reserved) = parameters.keys().find(|k| RESERVED.contains(&k.as_str())) {
        return Err(format!(
            "model parameter {reserved} is reserved by the Celln model contract"
        ));
    }
    object("", parameters, 1)?;
    let size = serde_json::to_vec(parameters)
        .map_err(|_| "model parameters cannot be serialized")?
        .len();
    if size > MAX_SERIALIZED_BYTES {
        return Err(format!(
            "model parameters serialize to {size} bytes; at most {MAX_SERIALIZED_BYTES} allowed"
        ));
    }
    Ok(())
}

/// Add validated parameters to the outgoing provider body as top-level
/// fields. A key already present is refused, never overwritten.
pub fn merge(body: &mut Value, parameters: &Map<String, Value>) -> Result<(), String> {
    if parameters.is_empty() {
        return Ok(());
    }
    validate(parameters)?;
    let body = body
        .as_object_mut()
        .ok_or("provider request is not an object")?;
    if let Some(key) = parameters.keys().find(|key| body.contains_key(*key)) {
        return Err(format!(
            "model parameter {key} collides with a field of the provider request"
        ));
    }
    body.extend(parameters.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(value: Value) -> Result<(), String> {
        validate(value.as_object().unwrap())
    }

    #[test]
    fn accepts_the_bounded_shapes_an_operator_needs() {
        assert!(check(json!({})).is_ok());
        assert!(check(json!({"chat_template_kwargs":{"enable_thinking":false}})).is_ok());
        assert!(check(
            json!({"temperature":0.2,"top_k":40,"seed":-7,"stop":["a","b"],
            "cache_prompt":true,"a":{"b":{"c":[1,true,"x"]}}})
        )
        .is_ok());
        let sixteen: Map<String, Value> = (0..16).map(|i| (format!("k{i}"), json!(i))).collect();
        assert!(validate(&sixteen).is_ok());
        assert!(check(json!({"s":"x".repeat(256),"k23456789012345678901234567890123456789012345678901234567890123":1})).is_ok());
    }

    #[test]
    fn every_reserved_key_is_refused_at_top_level_only() {
        for key in RESERVED {
            let mut map = Map::new();
            map.insert(key.into(), json!(1));
            let error = validate(&map).unwrap_err();
            assert!(error.contains(key) && error.contains("reserved"), "{error}");
            // Nested, the same word is an ordinary provider option name.
            assert!(check(json!({"options":{key:1}})).is_ok());
        }
        assert_eq!(RESERVED.len(), 14);
    }

    #[test]
    fn keys_are_bounded_lowercase_identifiers_at_any_depth() {
        let long = "k".repeat(65);
        for key in [
            "", "Upper", "9lead", "_lead", "da-sh", "sp ace", "dot.ted", "é", &long,
        ] {
            assert!(check(json!({key:1})).unwrap_err().contains("must match"));
            assert!(check(json!({"outer":{key:1}}))
                .unwrap_err()
                .contains("must match"));
        }
        let seventeen: Map<String, Value> = (0..17).map(|i| (format!("k{i}"), json!(i))).collect();
        assert!(validate(&seventeen).unwrap_err().contains("at most 16"));
    }

    #[test]
    fn values_depth_arrays_and_size_are_bounded() {
        assert!(check(json!({"a":null})).unwrap_err().contains("null"));
        assert!(check(json!({"a":{"b":null}})).is_err());
        assert!(check(json!({"a":"x".repeat(257)}))
            .unwrap_err()
            .contains("256"));
        assert!(check(json!({"a":"nul\0"})).is_err());
        assert!(check(json!({"a":["x".repeat(257)]})).is_err());
        // Top-level object is depth 1: three levels pass, four do not.
        assert!(check(json!({"a":{"b":{"c":1}}})).is_ok());
        assert!(check(json!({"a":{"b":{"c":{"d":1}}}}))
            .unwrap_err()
            .contains("deeper"));
        assert!(check(json!({"a":[1,2,3,4,5,6,7,8]})).is_ok());
        assert!(check(json!({"a":[1,2,3,4,5,6,7,8,9]}))
            .unwrap_err()
            .contains("array items"));
        for nested in [json!([[1]]), json!([{"x":1}]), json!([null])] {
            assert!(check(json!({"a":nested})).is_err());
        }
        // Individually legal values whose total exceeds the size bound.
        let big: Map<String, Value> = (0..9)
            .map(|i| (format!("k{i}"), json!("x".repeat(256))))
            .collect();
        assert!(validate(&big).unwrap_err().contains("2048"));
    }

    #[test]
    fn merge_adds_top_level_fields_and_refuses_collisions() {
        let mut body = json!({"model":"m","messages":[]});
        let parameters = json!({"chat_template_kwargs":{"enable_thinking":false},"top_k":1});
        merge(&mut body, parameters.as_object().unwrap()).unwrap();
        assert_eq!(
            body,
            json!({"model":"m","messages":[],"chat_template_kwargs":{"enable_thinking":false},"top_k":1})
        );
        // Not reserved, but already present in this outgoing body.
        let before = body.clone();
        assert!(merge(&mut body, json!({"top_k":2}).as_object().unwrap())
            .unwrap_err()
            .contains("collides"));
        assert_eq!(body, before);
        // Merge re-validates: a grant built without configure is still held.
        assert!(merge(&mut body, json!({"max_tokens":9999}).as_object().unwrap()).is_err());
        assert_eq!(body, before);
    }
}
