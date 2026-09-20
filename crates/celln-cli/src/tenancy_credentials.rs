//! Test-only independent consumer of scoped JWS conformance vectors.
//! Not wired to HTTP admission; durable ownership remains a separate boundary.
use super::tenancy_contract::{canonical, digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

type Refusal = &'static str;
const MALFORMED: Refusal = "AUTH_CRED_MALFORMED";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Subject {
    run_uid: String,
    turn_id: Option<String>,
    parent_incarnation: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Claims {
    api_version: String,
    iss: String,
    aud: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    decision_digest: String,
    budget_id: String,
    operation: String,
    subject: Subject,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Context {
    now: i64,
    expected_audience: String,
    expected_operation: String,
    cluster_id: String,
    namespace: String,
    namespace_uid: String,
    run_uid: String,
    run_spec_sha256: String,
    parent: Value,
    request_digest: String,
    route: Value,
    budget_id: String,
    seen_admission_jti: bool,
}

struct Verifier {
    issuer: String,
    keys: BTreeMap<String, VerifyingKey>,
}
impl Verifier {
    fn verify(
        &self,
        token: &str,
        decision: &[u8],
        ctx: &Context,
    ) -> Result<Option<Refusal>, Refusal> {
        if token.is_empty() || token.len() > 32768 || decision.len() > 262144 {
            return Err("AUTH_CRED_SIZE_EXCEEDED");
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
            return Err(MALFORMED);
        }
        let header = URL_SAFE_NO_PAD.decode(parts[0]).map_err(|_| MALFORMED)?;
        if header.len() > 1024 {
            return Err("AUTH_CRED_HEADER_SIZE");
        }
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| MALFORMED)?;
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| MALFORMED)?;
        // Validate I-JSON before serde can discard duplicate object fields.
        canonical(&header).map_err(|_| MALFORMED)?;
        canonical(&payload).map_err(|_| MALFORMED)?;
        let h: Header = serde_json::from_slice(&header).map_err(|_| "AUTH_CRED_UNKNOWN_FIELD")?;
        if h.alg != "EdDSA" {
            return Err("AUTH_CRED_ALG_UNSUPPORTED");
        }
        if h.typ != "celln-authorisation+jws" {
            return Err("AUTH_CRED_TYP_UNSUPPORTED");
        }
        let key = self.keys.get(&h.kid).ok_or("AUTH_CRED_KID_UNKNOWN")?;
        let signature = Signature::from_slice(&signature).map_err(|_| "AUTH_CRED_SIG_INVALID")?;
        let signed = format!("{}.{}", parts[0], parts[1]);
        key.verify_strict(signed.as_bytes(), &signature)
            .map_err(|_| "AUTH_CRED_SIG_INVALID")?;
        let canonical_decision = canonical(decision).map_err(|_| MALFORMED)?;
        let d: Value = serde_json::from_slice(&canonical_decision).map_err(|_| MALFORMED)?;
        validate_decision(&d)?;
        let c: Claims = serde_json::from_slice(&payload).map_err(|_| "AUTH_CRED_UNKNOWN_FIELD")?;
        if c.api_version != "celln.sympozium.ai/authorisation-credential-v1" {
            return Err("AUTH_VERSION_UNSUPPORTED");
        }
        if c.decision_digest != digest(&canonical_decision) {
            return Err("AUTH_DECISION_DIGEST_MISMATCH");
        }
        if c.iss != self.issuer {
            return Err("AUTH_ISS_MISMATCH");
        }
        let expected = match ctx.expected_operation.as_str() {
            "model.invoke" => "sympozium-model-gateway",
            "execution.start" | "execution.turn" | "execution.read" | "execution.cleanup" => {
                "celln-execution"
            }
            _ => return Err("AUTH_OPERATION_MISMATCH"),
        };
        if c.aud != ctx.expected_audience || expected != ctx.expected_audience {
            return Err("AUTH_AUD_MISMATCH");
        }
        let derived = c.operation == "model.invoke"
            && matches!(text(&d["operation"])?, "execution.start" | "execution.turn")
            && d["route"]["provider"] != "none";
        if c.operation != ctx.expected_operation
            || (!derived && c.operation != text(&d["operation"])?)
        {
            return Err("AUTH_OPERATION_MISMATCH");
        }
        if c.budget_id != text(&d["budget"]["budgetId"])? || ctx.budget_id != c.budget_id {
            return Err("AUTH_BUDGET_MISMATCH");
        }
        if c.subject.run_uid != text(&d["run"]["uid"])?
            || c.subject.turn_id.as_deref() != d["parent"]["turnId"].as_str()
            || c.subject.parent_incarnation.as_deref() != d["parent"]["incarnation"].as_str()
        {
            return Err("AUTH_SUBJECT_MISMATCH");
        }
        if c.jti.is_empty() {
            return Err(MALFORMED);
        }
        let now = ctx.now as i128;
        if c.nbf as i128 > now + 5 || c.iat as i128 > now + 5 {
            return Err("AUTH_TIME_NOT_YET_VALID");
        }
        let deadline = number(&d["budget"]["turnDeadlineUnix"])? as i128;
        if c.operation == "model.invoke" && now > deadline + 5 {
            return Err("AUTH_WORK_DEADLINE_EXPIRED");
        }
        if c.exp as i128 <= now - 5 {
            return Err("AUTH_TIME_EXPIRED");
        }
        if (c.iat as i128) < number(&d["windows"]["issuedAt"])? as i128 - 5 {
            return Err("AUTH_WINDOW_INVALID");
        }
        if ctx.cluster_id != text(&d["clusterId"])? {
            return Err("AUTH_SUBJECT_MISMATCH");
        }
        if ctx.namespace != text(&d["run"]["namespace"])?
            || ctx.namespace_uid != text(&d["run"]["namespaceUid"])?
        {
            return Err("AUTH_NAMESPACE_UID_MISMATCH");
        }
        if ctx.run_uid != text(&d["run"]["uid"])?
            || ctx.run_spec_sha256 != text(&d["run"]["specSha256"])?
        {
            return Err("AUTH_RUN_UID_MISMATCH");
        }
        if ctx.parent != d["parent"] {
            return Err("AUTH_PARENT_TURN_MISMATCH");
        }
        match c.operation.as_str() {
            "execution.start" | "execution.turn" => {
                let admission = number(&d["windows"]["admissionDeadline"])? as i128;
                if now > admission + 5 {
                    return Err("AUTH_ADMISSION_WINDOW_EXPIRED");
                }
                if c.exp as i128 > admission + 5 {
                    return Err("AUTH_WINDOW_INVALID");
                }
                if ctx.request_digest != text(&d["requestDigest"])? {
                    return Err("AUTH_REQUEST_BINDING_MISMATCH");
                }
                // Fixture disposition only; a runtime must recover via its
                // durable operation identity, never use JTI as an operation ID.
                if ctx.seen_admission_jti {
                    return Ok(Some("AUTH_ADMISSION_REPLAY"));
                }
            }
            "model.invoke" => {
                if c.exp as i128 > deadline + 5 {
                    return Err("AUTH_WINDOW_INVALID");
                }
                if ctx.route != d["route"] {
                    return Err("AUTH_ROUTE_MISMATCH");
                }
            }
            "execution.read" | "execution.cleanup" => {
                if c.exp as i128 - c.iat as i128 > 300 {
                    return Err("AUTH_WINDOW_INVALID");
                }
            }
            _ => return Err("AUTH_OPERATION_MISMATCH"),
        }
        Ok(None)
    }
}
fn text(v: &Value) -> Result<&str, Refusal> {
    v.as_str().ok_or(MALFORMED)
}
fn number(v: &Value) -> Result<i64, Refusal> {
    v.as_i64().ok_or(MALFORMED)
}
fn validate_decision(d: &Value) -> Result<(), Refusal> {
    if d["apiVersion"] != "celln.sympozium.ai/authorisation-decision-v1" {
        return Err("AUTH_VERSION_UNSUPPORTED");
    }
    if text(&d["clusterId"])?.is_empty() {
        return Err("AUTH_LIFECYCLE_INVALID");
    }
    let issued = number(&d["windows"]["issuedAt"])? as i128;
    let admission = number(&d["windows"]["admissionDeadline"])? as i128;
    let nbf = number(&d["windows"]["notBefore"])? as i128;
    if admission < issued || admission - issued > 60 || nbf < issued - 5 || nbf > admission {
        return Err("AUTH_WINDOW_INVALID");
    }
    let b = &d["budget"];
    for field in ["requests", "outputTokens"] {
        if number(&b["turnCap"][field])? > number(&b["runCap"][field])? {
            return Err("AUTH_BUDGET_MISMATCH");
        }
    }
    if d["lifecycle"] == "one-shot" {
        if number(&b["maxTurns"])? != 1 || number(&b["parentDeadlineUnix"])? != 0 {
            return Err("AUTH_LIFECYCLE_INVALID");
        }
    } else if number(&b["maxTurns"])? < 1
        || number(&b["parentDeadlineUnix"])? < number(&b["turnDeadlineUnix"])?
    {
        return Err("AUTH_LIFECYCLE_INVALID");
    }
    if number(&b["turnDeadlineUnix"])? as i128 <= issued {
        return Err("AUTH_LIFECYCLE_INVALID");
    }
    let tools = match &d["tools"] {
        Value::Null => &[][..],
        Value::Array(items) => items.as_slice(),
        _ => return Err(MALFORMED),
    };
    for tool in tools {
        let l = &tool["limits"];
        for (field, max) in [
            ("timeoutMillis", 300000),
            ("memoryBytes", 268435456),
            ("argumentBytes", 65536),
            ("outputBytes", 65536),
        ] {
            let v = number(&l[field])?;
            if v < 1 || v > max {
                return Err("AUTH_LIMIT_OUT_OF_RANGE");
            }
        }
        if l["workspace"] != "none"
            || !matches!(text(&l["effects"])?, "none" | "external-side-effects")
        {
            return Err("AUTH_LIMIT_OUT_OF_RANGE");
        }
    }
    let r = &d["route"];
    if r["provider"] == "none" {
        if r["auth"] != "none"
            || !r["credentialSource"].is_null()
            || !r["modelConnectionUid"].is_null()
        {
            return Err("AUTH_ROUTE_MISMATCH");
        }
        return Ok(());
    }
    if r["streaming"].as_bool().ok_or(MALFORMED)? {
        return Err("AUTH_STREAMING_UNSUPPORTED");
    }
    if !matches!(text(&r["protocol"])?, "openai-chat" | "anthropic-messages") {
        return Err("AUTH_PROTOCOL_UNSUPPORTED");
    }
    match text(&r["auth"])? {
        "secret" if !r["credentialSource"].is_null() => (),
        "none" if r["credentialSource"].is_null() => (),
        _ => return Err("AUTH_ROUTE_MISMATCH"),
    }
    Ok(())
}

fn fixtures() -> Value {
    use std::io::Read;
    let data = include_bytes!("../../../tests/fixtures/celln-authorisation/v1/cases.json.gz");
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(&data[..])
        .take(4 * 1024 * 1024)
        .read_to_end(&mut decoded)
        .unwrap();
    serde_json::from_slice(&decoded).unwrap()
}
fn verifier() -> Verifier {
    let jwks: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/celln-authorisation/v1/signing/test-jwks.json"
    ))
    .unwrap();
    let keys = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| {
            let raw = URL_SAFE_NO_PAD.decode(key["x"].as_str().unwrap()).unwrap();
            (
                key["kid"].as_str().unwrap().to_owned(),
                VerifyingKey::from_bytes(&raw.try_into().unwrap()).unwrap(),
            )
        })
        .collect();
    Verifier {
        issuer: "sympozium-control-plane".into(),
        keys,
    }
}
#[test]
fn every_shared_credential_vector_has_exact_disposition() {
    let cases = fixtures();
    let verifier = verifier();
    let mut count = 0;
    for vector in cases["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["evaluator"] == "verify")
    {
        count += 1;
        let decision = cases["decisions"][vector["decisionRef"].as_str().unwrap()]["canonical"]
            .as_str()
            .unwrap();
        let ctx: Context = serde_json::from_value(vector["verify"].clone()).unwrap();
        let result = verifier.verify(
            vector["credential"].as_str().unwrap(),
            decision.as_bytes(),
            &ctx,
        );
        let expected = &vector["expect"];
        match expected["outcome"].as_str().unwrap() {
            "accept" => assert_eq!(result, Ok(None), "{}", vector["name"]),
            "recover" => assert_eq!(
                result,
                Ok(Some(expected["reason"].as_str().unwrap())),
                "{}",
                vector["name"]
            ),
            "reject" => assert_eq!(
                result,
                Err(expected["reason"].as_str().unwrap()),
                "{}",
                vector["name"]
            ),
            _ => panic!("unexpected fixture disposition"),
        }
    }
    assert_eq!(count, 24, "pinned credential inventory changed");
}

#[test]
fn untrusted_headers_and_removed_keys_cannot_authorize() {
    let cases = fixtures();
    let vector = &cases["vectors"][0];
    let raw = cases["decisions"][vector["decisionRef"].as_str().unwrap()]["canonical"]
        .as_str()
        .unwrap();
    let ctx: Context = serde_json::from_value(vector["verify"].clone()).unwrap();
    let token = vector["credential"].as_str().unwrap();
    let parts: Vec<_> = token.split('.').collect();
    for header in [
        r#"{"alg":"EdDSA","typ":"celln-authorisation+jws","kid":"test-key-1","jku":"https://attacker.invalid/key"}"#,
        r#"{"alg":"EdDSA","alg":"none","typ":"celln-authorisation+jws","kid":"test-key-1"}"#,
        r#"{"alg":"none","typ":"celln-authorisation+jws","kid":"test-key-1"}"#,
        r#"{"alg":"HS256","typ":"celln-authorisation+jws","kid":"test-key-1"}"#,
    ] {
        let altered = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            parts[1],
            parts[2]
        );
        assert!(verifier().verify(&altered, raw.as_bytes(), &ctx).is_err());
    }
    let mut revoked = verifier();
    revoked.keys.remove("test-key-1");
    assert_eq!(
        revoked.verify(token, raw.as_bytes(), &ctx),
        Err("AUTH_CRED_KID_UNKNOWN")
    );
    for invalid in [
        String::new(),
        "a.b".into(),
        "a.b.c.d".into(),
        "x".repeat(32769),
    ] {
        assert!(verifier().verify(&invalid, raw.as_bytes(), &ctx).is_err());
    }
}

#[test]
fn model_credential_cannot_become_parent_cleanup_authority() {
    let cases = fixtures();
    let vector = cases["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "model-after-admission-window")
        .unwrap();
    let raw = cases["decisions"][vector["decisionRef"].as_str().unwrap()]["canonical"]
        .as_str()
        .unwrap();
    let mut ctx: Context = serde_json::from_value(vector["verify"].clone()).unwrap();
    ctx.expected_audience = "celln-execution".into();
    ctx.expected_operation = "execution.cleanup".into();
    assert_eq!(
        verifier().verify(vector["credential"].as_str().unwrap(), raw.as_bytes(), &ctx),
        Err("AUTH_AUD_MISMATCH")
    );
}
