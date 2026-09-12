//! Independent Rust consumer for the Sympozium #496 integer-only JCS profile.
//! Test-only prerequisite for #500; does not admit execution or verify JWS.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

const MAX_BYTES: usize = 262144;
const MAX_INTEGER: i64 = 9007199254740991;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded integer-only I-JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict, E> {
                if !(-MAX_INTEGER..=MAX_INTEGER).contains(&v) {
                    return Err(E::custom("integer outside safe range"));
                }
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict, E> {
                if v > MAX_INTEGER as u64 {
                    return Err(E::custom("integer outside safe range"));
                }
                Ok(Strict(Value::Number(v.into())))
            }
            // No visit_f64: floats, exponents and negative zero refuse.
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    out.push(v);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(key) = a.next_key::<String>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                    let Strict(value) = a.next_value()?;
                    out.insert(key, value);
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn canonical(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.is_empty() || raw.len() > MAX_BYTES {
        return Err("size exceeded");
    }
    let mut parser = serde_json::Deserializer::from_slice(raw);
    let Strict(value) = Strict::deserialize(&mut parser).map_err(|_| "invalid I-JSON")?;
    parser.end().map_err(|_| "trailing JSON")?;
    let mut out = Vec::new();
    encode(&value, &mut out);
    Ok(out)
}
fn encode(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<_> = object.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key).unwrap();
                out.push(b':');
                encode(&object[key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                encode(item, out);
            }
            out.push(b']');
        }
        _ => serde_json::to_writer(out, value).unwrap(),
    }
}
fn digest(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

#[test]
fn vendored_contract_bundle_matches_external_pin() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/celln-authorisation/v1");
    let sums = std::fs::read(root.join("bundle/SHA256SUMS")).unwrap();
    let expected = "sha256:e5a26a8a31d388072067c9d239ff2908fb962effd08b234f152dc5a0ad3dad34";
    assert_eq!(digest(&sums), expected);
    assert_eq!(
        std::fs::read_to_string(root.join("bundle/BUNDLE.sha256"))
            .unwrap()
            .trim(),
        expected
    );
    let text = std::str::from_utf8(&sums).unwrap();
    assert_eq!(text.lines().count(), 8);
    for line in text.lines() {
        let (hash, name) = line.split_once("  ").unwrap();
        assert_eq!(
            digest(&std::fs::read(root.join(name)).unwrap()),
            format!("sha256:{hash}")
        );
    }
}

#[test]
fn shared_go_decisions_and_requests_match_independent_rust_encoding() {
    use std::io::Read;
    let compressed = include_bytes!("../../../tests/fixtures/celln-authorisation/v1/cases.json.gz");
    let decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut raw = Vec::new();
    decoder.take(4 * 1024 * 1024).read_to_end(&mut raw).unwrap();
    let cases: Value = serde_json::from_slice(&raw).unwrap();
    let decisions = cases["decisions"].as_object().unwrap();
    assert_eq!(decisions.len(), 8, "pinned fixture inventory changed");
    for (expected_digest, fixture) in decisions {
        let original = fixture["canonical"].as_str().unwrap();
        let value: Value = serde_json::from_str(original).unwrap();
        let reencoded = canonical(&serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert_eq!(reencoded, original.as_bytes());
        assert_eq!(digest(&reencoded), *expected_digest);
        let request = fixture["requestCanonical"].as_str().unwrap();
        assert_eq!(canonical(request.as_bytes()).unwrap(), request.as_bytes());
        assert_eq!(
            digest(request.as_bytes()),
            value["requestDigest"].as_str().unwrap()
        );
    }
}

#[test]
fn strict_parser_refuses_ambiguous_and_unbounded_inputs() {
    for raw in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        "1.0",
        "1e0",
        "-0",
        "9007199254740992",
        "-9007199254740992",
        r#""\ud800""#,
        r#""\udfff""#,
        "{} {}",
    ] {
        assert!(canonical(raw.as_bytes()).is_err(), "accepted {raw}");
    }
    assert!(canonical(&[b'"', 0xff, b'"']).is_err());
    assert!(canonical(&vec![b' '; MAX_BYTES + 1]).is_err());
    let nested = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    assert!(canonical(nested.as_bytes()).is_err());
    assert_eq!(
        canonical("{\"\u{e000}\":1,\"\u{10000}\":2}".as_bytes()).unwrap(),
        "{\"\u{10000}\":2,\"\u{e000}\":1}".as_bytes()
    );
}
