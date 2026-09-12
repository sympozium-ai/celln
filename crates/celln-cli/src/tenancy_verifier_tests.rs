use super::*;
use ed25519_dalek::{Signer, SigningKey};

const PUBLIC: &[u8] =
    include_bytes!("../../../tests/fixtures/celln-authorisation/v1/signing/test-jwks.json");

#[test]
fn malformed_reload_is_atomic_and_private_keys_refuse() {
    let v = Verifier::from_jwks("sympozium-control-plane".into(), PUBLIC).unwrap();
    for raw in [
        b"{\"keys\":[]}".as_slice(),
        b"{}",
        b"{\"keys\":[],\"keys\":[]}",
    ] {
        assert!(v.reload_jwks(raw).is_err());
    }
    let mut keys: Value = serde_json::from_slice(PUBLIC).unwrap();
    keys["keys"][0]["d"] = Value::String("private-canary".into());
    assert!(v.reload_jwks(&serde_json::to_vec(&keys).unwrap()).is_err());
    let c = fixtures();
    let vector = &c["vectors"][0];
    let d = c["decisions"][vector["decisionRef"].as_str().unwrap()]["canonical"]
        .as_str()
        .unwrap();
    let ctx = serde_json::from_value(vector["verify"].clone()).unwrap();
    assert_eq!(
        v.verify(vector["credential"].as_str().unwrap(), d.as_bytes(), &ctx),
        Ok(None)
    );
    assert!(Verifier::from_jwks(String::new(), PUBLIC).is_err());
}

#[test]
fn schema_rejects_signed_unknown_and_invalid_authority() {
    let c = fixtures();
    let vector = &c["vectors"][0];
    let original: Value = serde_json::from_str(
        c["decisions"][vector["decisionRef"].as_str().unwrap()]["canonical"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let token = vector["credential"].as_str().unwrap();
    let parts: Vec<_> = token.split('.').collect();
    let original_claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    let ctx = serde_json::from_value(vector["verify"].clone()).unwrap();
    for field in ["unknown", "null-tools", "invalid-kind", "invalid-uid"] {
        let mut d = original.clone();
        match field {
            "unknown" => d["ambientAuthority"] = Value::Bool(true),
            "null-tools" => d["tools"] = Value::Null,
            "invalid-kind" => d["kind"] = Value::String("Other".into()),
            _ => d["run"]["uid"] = Value::String(String::new()),
        }
        let raw = canonical(&serde_json::to_vec(&d).unwrap()).unwrap();
        let mut claims = original_claims.clone();
        claims["decisionDigest"] = Value::String(digest(&raw));
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{}.{payload}", parts[0]);
        // Publicly known fixture seed, confined to test code.
        let signature = SigningKey::from_bytes(&[0x11; 32]).sign(signing_input.as_bytes());
        let signed = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        assert_eq!(
            verifier().verify(&signed, &raw, &ctx),
            Err(MALFORMED),
            "{field}"
        );
    }
}

#[test]
fn valid_overlap_rotation_can_run_concurrently_with_verification() {
    let v =
        std::sync::Arc::new(Verifier::from_jwks("sympozium-control-plane".into(), PUBLIC).unwrap());
    let c = fixtures();
    let vector = c["vectors"][0].clone();
    let d = c["decisions"][vector["decisionRef"].as_str().unwrap()]["canonical"]
        .as_str()
        .unwrap()
        .to_owned();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let v = v.clone();
            let vector = vector.clone();
            let d = d.clone();
            scope.spawn(move || {
                for _ in 0..20 {
                    let ctx = serde_json::from_value(vector["verify"].clone()).unwrap();
                    assert_eq!(
                        v.verify(vector["credential"].as_str().unwrap(), d.as_bytes(), &ctx),
                        Ok(None)
                    );
                }
            });
        }
        for _ in 0..20 {
            v.reload_jwks(PUBLIC).unwrap();
        }
    });
}
