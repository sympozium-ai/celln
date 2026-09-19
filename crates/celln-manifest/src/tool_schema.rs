//! Bounded, closed JSON-schema subset for immutable tool argument/result data.
//! No I/O, reference resolution, executable authority or remote schema fetching.
use crate::Hash;
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub const PROFILE: &str = "celln.tool-schema/v1";
pub const MAX_SCHEMA_BYTES: usize = 32768;
pub const MAX_VALUE_BYTES: usize = 65536;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum Node {
    Object {
        properties: BTreeMap<String, Node>,
        required: Vec<String>,
        #[serde(rename = "additionalProperties")]
        additional_properties: bool,
    },
    Array {
        items: Box<Node>,
        #[serde(rename = "minItems")]
        min_items: usize,
        #[serde(rename = "maxItems")]
        max_items: usize,
    },
    String {
        #[serde(rename = "minLength")]
        min_length: usize,
        #[serde(rename = "maxLength")]
        max_length: usize,
    },
    Integer {
        minimum: i64,
        maximum: i64,
    },
    Boolean {},
}

pub struct ToolSchema {
    identity: Hash,
    node: Node,
}

impl ToolSchema {
    /// Expected identity is the hash of exact schema bytes, not normalized JSON.
    pub fn parse(bytes: &[u8], expected: &Hash) -> Result<Self, String> {
        if bytes.len() > MAX_SCHEMA_BYTES {
            return Err("schema exceeds 32 KiB".into());
        }
        let identity = Hash::of(bytes);
        if &identity != expected {
            return Err("schema artifact identity mismatch".into());
        }
        let value = parse_json(bytes)?;
        let node: Node =
            serde_json::from_value(value).map_err(|_| "unsupported or malformed tool schema")?;
        node.check(0, &mut 0)?;
        Ok(Self { identity, node })
    }

    pub fn identity(&self) -> &Hash {
        &self.identity
    }

    /// Caller supplies the effective argument/result byte ceiling. Validation
    /// cannot raise it. Integer values must use signed-64-bit integer encoding;
    /// float/exponent spellings are explicitly unsupported in this profile.
    pub fn validate(&self, bytes: &[u8], max_bytes: usize) -> Result<(), String> {
        if max_bytes == 0 || max_bytes > MAX_VALUE_BYTES || bytes.len() > max_bytes {
            return Err("tool value exceeds permitted byte ceiling".into());
        }
        let value = parse_json(bytes)?;
        self.node.matches(&value)
    }
}

impl Node {
    fn check(&self, depth: usize, nodes: &mut usize) -> Result<(), String> {
        *nodes += 1;
        if depth > 4 || *nodes > 128 {
            return Err("schema nesting or node limit exceeded".into());
        }
        match self {
            Self::Object {
                properties,
                required,
                additional_properties,
            } => {
                if *additional_properties
                    || properties.len() > 32
                    || required.len() > properties.len()
                    || required.iter().collect::<BTreeSet<_>>().len() != required.len()
                    || required.iter().any(|k| !properties.contains_key(k))
                    || properties.keys().any(|k| {
                        k.is_empty()
                            || k.len() > 64
                            || !k
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    })
                {
                    return Err(
                        "object schema must be closed with unique declared properties".into(),
                    );
                }
                for node in properties.values() {
                    node.check(depth + 1, nodes)?;
                }
            }
            Self::Array {
                items,
                min_items,
                max_items,
            } => {
                if min_items > max_items || *max_items > 64 {
                    return Err("invalid array bounds".into());
                }
                items.check(depth + 1, nodes)?;
            }
            Self::String {
                min_length,
                max_length,
            } if min_length > max_length || *max_length > 4096 => {
                return Err("invalid string bounds".into());
            }
            Self::Integer { minimum, maximum } if minimum > maximum => {
                return Err("invalid integer bounds".into())
            }
            _ => {}
        }
        Ok(())
    }

    fn matches(&self, value: &Value) -> Result<(), String> {
        match (self, value) {
            (
                Self::Object {
                    properties,
                    required,
                    ..
                },
                Value::Object(values),
            ) => {
                if required.iter().any(|k| !values.contains_key(k)) {
                    return Err("required tool field missing".into());
                }
                for (key, value) in values {
                    properties
                        .get(key)
                        .ok_or("undeclared tool field")?
                        .matches(value)?;
                }
            }
            (
                Self::Array {
                    items,
                    min_items,
                    max_items,
                },
                Value::Array(values),
            ) => {
                if values.len() < *min_items || values.len() > *max_items {
                    return Err("tool array outside bounds".into());
                }
                for value in values {
                    items.matches(value)?;
                }
            }
            (
                Self::String {
                    min_length,
                    max_length,
                },
                Value::String(value),
            ) => {
                let length = value.chars().count();
                if length < *min_length || length > *max_length {
                    return Err("tool string outside bounds".into());
                }
            }
            (Self::Integer { minimum, maximum }, Value::Number(value)) => {
                let value = value
                    .as_i64()
                    .ok_or("unsupported non-i64 integer encoding")?;
                if value < *minimum || value > *maximum {
                    return Err("tool integer outside bounds".into());
                }
            }
            (Self::Boolean {}, Value::Bool(_)) => {}
            _ => return Err("tool value type mismatch".into()),
        }
        Ok(())
    }
}

// Reject duplicate keys before serde's normal object decoding can overwrite
// them. Byte, depth and node bounds also apply to malformed input documents.
struct Bounded<'a> {
    depth: usize,
    nodes: &'a mut usize,
}
impl<'de> DeserializeSeed<'de> for Bounded<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        *self.nodes += 1;
        if self.depth > 16 || *self.nodes > 4096 {
            return Err(de::Error::custom("JSON complexity exceeded"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Bounded<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(v.into())
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(Bounded {
            depth: self.depth + 1,
            nodes: self.nodes,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON key"));
            }
            let value = map.next_value_seed(Bounded {
                depth: self.depth + 1,
                nodes: self.nodes,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
fn parse_json(bytes: &[u8]) -> Result<Value, String> {
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let value = Bounded {
        depth: 0,
        nodes: &mut 0,
    }
    .deserialize(&mut d)
    .map_err(|_| "malformed, duplicate-key or over-complex JSON")?;
    d.end().map_err(|_| "trailing JSON data")?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn schema(value: &str) -> Result<ToolSchema, String> {
        ToolSchema::parse(value.as_bytes(), &Hash::of(value.as_bytes()))
    }
    const OBJECT: &str = r#"{"type":"object","properties":{"count":{"type":"integer","minimum":-2,"maximum":42},"label":{"type":"string","minLength":1,"maxLength":2},"ok":{"type":"boolean"}},"required":["count"],"additionalProperties":false}"#;

    #[test]
    fn closed_object_and_scalar_bounds() {
        let s = schema(OBJECT).unwrap();
        for v in [
            r#"{"count":42}"#,
            r#"{"count":-2,"label":"é🦀","ok":false}"#,
        ] {
            assert!(s.validate(v.as_bytes(), 1024).is_ok(), "{v}");
        }
        for v in [
            r#"{}"#,
            r#"{"count":43}"#,
            r#"{"count":-3}"#,
            r#"{"count":1.0}"#,
            r#"{"count":1e0}"#,
            r#"{"count":"1"}"#,
            r#"{"count":1,"extra":true}"#,
            r#"{"count":1,"label":"abc"}"#,
            r#"{"count":1,"ok":null}"#,
            r#"{"count":1,"count":2}"#,
            r#"{"count":1} {}"#,
        ] {
            assert!(s.validate(v.as_bytes(), 1024).is_err(), "{v}");
        }
        assert!(s.validate(br#"{"count":1}"#, 1).is_err());
        assert!(s.validate(br#"{"count":1}"#, 0).is_err());
        assert!(s.validate(br#"{"count":1}"#, 65537).is_err());
    }

    #[test]
    fn array_and_integer_encoding_limits() {
        let s = schema(r#"{"type":"array","items":{"type":"integer","minimum":-9223372036854775808,"maximum":9223372036854775807},"minItems":1,"maxItems":2}"#).unwrap();
        for v in ["[-9223372036854775808]", "[9223372036854775807,0]"] {
            assert!(s.validate(v.as_bytes(), 1024).is_ok());
        }
        for v in [
            "[]",
            "[1,2,3]",
            "[9223372036854775808]",
            "[-9223372036854775809]",
            "[1.5]",
            "[true]",
        ] {
            assert!(s.validate(v.as_bytes(), 1024).is_err(), "{v}");
        }
    }

    #[test]
    fn unsupported_features_and_malformed_schemas_refuse() {
        for doc in [
            r#"{"type":"boolean","default":true}"#,
            r#"{"type":"boolean","$ref":"https://example.com/schema"}"#,
            r#"{"type":"boolean","enum":[true]}"#,
            r#"{"type":"boolean","type":"string"}"#,
            r#"{"type":"number"}"#,
            r#"{"type":"string","minLength":0,"maxLength":4097}"#,
            r#"{"type":"string","minLength":2,"maxLength":1}"#,
            r#"{"type":"string","maxLength":2}"#,
            r#"{"type":"integer","minimum":3,"maximum":2}"#,
            r#"{"type":"array","items":{"type":"boolean"},"minItems":0,"maxItems":65}"#,
            r#"{"type":"object","properties":{},"required":[],"additionalProperties":true}"#,
            r#"{"type":"object","properties":{},"required":["missing"],"additionalProperties":false}"#,
            r#"{"type":"object","properties":{"a":{"type":"boolean"}},"required":["a","a"],"additionalProperties":false}"#,
            r#"{"type":"object","properties":{"a":{"type":"boolean"},"a":{"type":"boolean"}},"required":[],"additionalProperties":false}"#,
        ] {
            assert!(schema(doc).is_err(), "{doc}");
        }
        assert!(ToolSchema::parse(OBJECT.as_bytes(), &Hash::of(b"wrong")).is_err());
        assert!(schema(&" ".repeat(MAX_SCHEMA_BYTES + 1)).is_err());
        let mut nested = r#"{"type":"boolean"}"#.to_owned();
        for _ in 0..5 {
            nested = format!(r#"{{"type":"array","minItems":0,"maxItems":1,"items":{nested}}}"#);
        }
        assert!(schema(&nested).is_err());
    }

    #[test]
    fn parser_limits_malformed_data_before_validation() {
        let s = schema(r#"{"type":"boolean"}"#).unwrap();
        let nested = format!("{}true{}", "[".repeat(20), "]".repeat(20));
        assert!(s.validate(nested.as_bytes(), 1024).is_err());
        let many = format!("[{}]", vec!["true"; 4097].join(","));
        assert!(s.validate(many.as_bytes(), 65536).is_err());
        assert!(s.validate(&[0xff], 1024).is_err());
    }
}
