use super::*;
use std::io::Read;

#[test]
fn model_request_canonical_bounds() {
    for depth in [64, 65] {
        let raw = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(canonical_model_request(raw.as_bytes()).is_err(), depth > 64);
    }
    assert!(canonical_model_request(&vec![b' '; 262145]).is_err());
}

#[test]
fn shared_model_request_canonical_vectors() {
    let raw = include_bytes!("../../../tests/fixtures/celln-model-requests/v1.json");
    let fixture: Value = serde_json::from_slice(raw).unwrap();
    assert_eq!(
        fixture["apiVersion"],
        "celln.sympozium.ai/model-request-conformance-v1"
    );
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 11);
    for vector in vectors {
        let result = canonical_model_request(vector["request"].as_str().unwrap().as_bytes());
        if let Some(expected) = vector["canonical"].as_str() {
            let (body, digest) = result.unwrap();
            assert_eq!(body, expected.as_bytes(), "{}", vector["name"]);
            assert_eq!(digest, crate::tenancy_contract::digest(expected.as_bytes()));
        } else {
            assert!(result.is_err(), "{}", vector["name"]);
        }
    }
}

#[test]
fn paired_capabilities_are_isolated_redacted_and_cancelled() {
    let bytes = include_bytes!("../../../tests/fixtures/celln-authorisation/v1/cases.json.gz");
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_end(&mut raw)
        .unwrap();
    let cases: Value = serde_json::from_slice(&raw).unwrap();
    let vector = |name: &str| {
        cases["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap()
    };
    let initial = vector("harness-one-shot");
    let model = vector("model-after-admission-window");
    let foreign = vector("enduring-model-after-admission-window");
    let decision = cases["decisions"][initial["decisionRef"].as_str().unwrap()]["canonical"]
        .as_str()
        .unwrap();
    let receiver: Context = serde_json::from_value(initial["verify"].clone()).unwrap();
    let execution = initial["credential"].as_str().unwrap();
    let bearer = model["credential"].as_str().unwrap();
    let verifier = Verifier::from_jwks(
        "sympozium-control-plane".into(),
        include_bytes!("../../../tests/fixtures/celln-authorisation/v1/signing/test-jwks.json"),
    )
    .unwrap();
    let parent = Control::new(Duration::from_secs(300)).unwrap();
    let admit = || {
        ModelContext::admit(
            &verifier,
            execution.into(),
            bearer.into(),
            decision.as_bytes(),
            &receiver,
            &parent,
        )
        .unwrap()
    };
    let mut replay = receiver.clone();
    replay.seen_admission_jti = true;
    assert!(ModelContext::admit(
        &verifier,
        execution.into(),
        bearer.into(),
        decision.as_bytes(),
        &replay,
        &parent
    )
    .is_err());
    let mut first = admit();
    let mut sibling = admit();
    assert!(!format!("{first:?}").contains(bearer));
    first
        .with_bearer(|value, control| {
            assert_eq!(value, bearer);
            assert!(control.remaining() <= Duration::from_secs(110));
        })
        .unwrap();
    assert!(ModelContext::admit(
        &verifier,
        execution.into(),
        foreign["credential"].as_str().unwrap().into(),
        decision.as_bytes(),
        &receiver,
        &parent
    )
    .is_err());
    assert!(ModelContext::admit(
        &verifier,
        bearer.into(),
        execution.into(),
        decision.as_bytes(),
        &receiver,
        &parent
    )
    .is_err());
    first.close();
    assert!(first.bearer.is_none());
    assert!(first
        .with_bearer(|_, _| panic!("closed callback invoked"))
        .is_err());
    assert!(sibling.with_bearer(|_, _| ()).is_ok());
    parent.cancel();
    assert!(sibling
        .with_bearer(|_, _| panic!("cancelled callback invoked"))
        .is_err());
    assert!(sibling.bearer.is_none());
    assert!(ModelContext::admit(
        &verifier,
        execution.into(),
        bearer.into(),
        decision.as_bytes(),
        &receiver,
        &parent
    )
    .is_err());
}
