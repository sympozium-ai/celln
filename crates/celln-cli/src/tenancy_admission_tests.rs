use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    sync::Arc,
    time::Duration,
};

struct Fixture {
    token: String,
    decision: Vec<u8>,
    request: Vec<u8>,
    context: Context,
}
impl Fixture {
    fn named(name: &str) -> Self {
        let mut raw = Vec::new();
        flate2::read::GzDecoder::new(
            include_bytes!("../../../tests/fixtures/celln-authorisation/v1/cases.json.gz")
                .as_slice(),
        )
        .read_to_end(&mut raw)
        .unwrap();
        let cases: Value = serde_json::from_slice(&raw).unwrap();
        let v = cases["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == name)
            .unwrap();
        let d = &cases["decisions"][v["decisionRef"].as_str().unwrap()];
        Self {
            token: v["credential"].as_str().unwrap().into(),
            decision: d["canonical"].as_str().unwrap().as_bytes().to_vec(),
            request: d["requestCanonical"].as_str().unwrap().as_bytes().to_vec(),
            context: serde_json::from_value(v["verify"].clone()).unwrap(),
        }
    }
    fn claim(&self, journal: &Journal) -> Result<Claim, Error> {
        let verifier = Verifier::from_jwks(
            "sympozium-control-plane".into(),
            include_bytes!("../../../tests/fixtures/celln-authorisation/v1/signing/test-jwks.json"),
        )
        .unwrap();
        journal.claim(
            &verifier,
            &self.token,
            &self.decision,
            &self.request,
            &self.context,
        )
    }
    fn turn(id: &str) -> Self {
        let mut f = Self::named("enduring-turn");
        let mut d: Value = serde_json::from_slice(&f.decision).unwrap();
        let mut request: Value = serde_json::from_slice(&f.request).unwrap();
        request["turnId"] = id.into();
        f.request = canonical(&serde_json::to_vec(&request).unwrap()).unwrap();
        d["parent"]["turnId"] = id.into();
        d["requestDigest"] = digest(&f.request).into();
        f.context.parent = d["parent"].clone();
        f.context.request_digest = digest(&f.request);
        f.resign(d);
        f
    }
    fn access(&mut self, operation: &str) {
        self.context.expected_operation = operation.into();
        let mut d: Value = serde_json::from_slice(&self.decision).unwrap();
        d["operation"] = operation.into();
        self.resign(d);
    }
    fn lookup(&self, journal: &Journal) -> Result<Record, Error> {
        let verifier = Verifier::from_jwks(
            "sympozium-control-plane".into(),
            include_bytes!("../../../tests/fixtures/celln-authorisation/v1/signing/test-jwks.json"),
        )
        .unwrap();
        journal.access(&verifier, &self.token, &self.decision, &self.context)
    }
    fn resign(&mut self, d: Value) {
        self.decision = canonical(&serde_json::to_vec(&d).unwrap()).unwrap();
        let parts: Vec<_> = self.token.split('.').collect();
        let mut claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        claims["operation"] = d["operation"].clone();
        if matches!(
            self.context.expected_operation.as_str(),
            "execution.read" | "execution.cleanup"
        ) {
            claims["iat"] = self.context.now.into();
            claims["nbf"] = self.context.now.into();
            claims["exp"] = (self.context.now + 120).into();
        }
        claims["decisionDigest"] = digest(&self.decision).into();
        claims["jti"] = format!("jti-{}", &digest(&self.decision)[7..39]).into();
        if !d["parent"]["turnId"].is_null() {
            claims["subject"]["turnId"] = d["parent"]["turnId"].clone();
        }
        let input = format!(
            "{}.{}",
            parts[0],
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let signature = SigningKey::from_bytes(&[0x11; 32]).sign(input.as_bytes());
        self.token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    }
}
fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}
fn fresh(claim: Claim) -> Fresh {
    match claim {
        Claim::Fresh(f) => f,
        _ => panic!("expected exactly one fresh claim"),
    }
}
fn receipt() -> Outcome {
    Outcome::Receipt {
        digest: celln_manifest::Hash::of(b"fixture-receipt").0,
    }
}

#[test]
fn duplicate_and_restart_recover_without_new_execution_authority() {
    let root = private_root();
    let j = Journal::open(root.path(), 4).unwrap();
    let f = Fixture::named("direct-one-shot");
    let ticket = fresh(f.claim(&j).unwrap());
    assert!(matches!(f.claim(&j), Ok(Claim::Recovery(_))));
    j.finish(&ticket, receipt()).unwrap();
    j.finish(&ticket, receipt()).unwrap();
    assert_eq!(
        j.finish(&ticket, Outcome::Refused),
        Err(Error::RequestConflict)
    );
    let restarted = Journal::open(root.path(), 4).unwrap();
    match f.claim(&restarted).unwrap() {
        Claim::Recovery(r) => {
            assert_eq!(r.owner(), j.owner);
            assert_ne!(r.owner(), restarted.owner);
            assert_eq!(r.outcome(), Some(&receipt()));
        }
        _ => panic!("restart created duplicate authority"),
    }
    assert_eq!(
        restarted.finish(&ticket, receipt()),
        Err(Error::RequestConflict)
    );
    for entry in fs::read_dir(root.path()).unwrap() {
        let raw = fs::read(entry.unwrap().path()).unwrap();
        assert!(!raw.windows(f.token.len()).any(|v| v == f.token.as_bytes()));
        assert!(!String::from_utf8_lossy(&raw).contains("direct-input"));
    }
}

#[test]
fn credentials_and_payload_are_verified_before_duplicate_lookup() {
    let root = private_root();
    let j = Journal::open(root.path(), 4).unwrap();
    let mut f = Fixture::named("direct-one-shot");
    let ticket = fresh(f.claim(&j).unwrap());
    fs::write(j.path(&ticket.record.scope), b"corrupt-record").unwrap();
    f.request = b"{}".to_vec();
    assert!(matches!(
        f.claim(&j),
        Err(Error::Credential("AUTH_REQUEST_BINDING_MISMATCH"))
    ));
    f.context.namespace_uid = "other-tenant".into();
    assert!(matches!(
        f.claim(&j),
        Err(Error::Credential("AUTH_NAMESPACE_UID_MISMATCH"))
    ));
    let good = Fixture::named("direct-one-shot");
    assert!(matches!(good.claim(&j), Err(Error::Unavailable)));
}

#[test]
fn renewed_authority_cannot_reset_original_operation_ceiling() {
    let root = private_root();
    let journal = Journal::open(root.path(), 4).unwrap();
    let mut f = Fixture::named("harness-one-shot");
    fresh(f.claim(&journal).unwrap());
    let mut d: Value = serde_json::from_slice(&f.decision).unwrap();
    d["budget"]["runCap"]["requests"] =
        (d["budget"]["runCap"]["requests"].as_u64().unwrap() + 1).into();
    d["budget"]["turnCap"]["requests"] =
        (d["budget"]["turnCap"]["requests"].as_u64().unwrap() + 1).into();
    f.resign(d);
    assert!(matches!(f.claim(&journal), Err(Error::RequestConflict)));
}

#[test]
fn expiry_safe_read_and_cleanup_do_not_reopen_or_widen_authority() {
    let root = private_root();
    let journal = Journal::open(root.path(), 10).unwrap();
    let mut parent = Fixture::named("parent-create");
    let start = fresh(parent.claim(&journal).unwrap());
    journal.finish(&start, receipt()).unwrap();
    let mut turn = Fixture::turn("turn-1");
    let child = fresh(turn.claim(&journal).unwrap());
    parent.access("execution.read");
    assert!(!parent.lookup(&journal).unwrap().fenced());
    turn.access("execution.cleanup");
    assert!(turn.lookup(&journal).unwrap().fenced());
    assert!(!parent.lookup(&journal).unwrap().fenced());
    journal.finish(&child, receipt()).unwrap();
    let next = fresh(Fixture::turn("turn-2").claim(&journal).unwrap());
    journal.finish(&next, receipt()).unwrap();
    parent.access("execution.cleanup");
    assert!(parent.lookup(&journal).unwrap().fenced());
    assert!(matches!(
        Fixture::turn("turn-3").claim(&journal),
        Err(Error::Fenced)
    ));
    parent.context.now = 1790000400;
    parent.access("execution.read");
    assert!(parent.lookup(&journal).unwrap().fenced());
    parent.access("execution.cleanup");
    assert!(parent.lookup(&journal).unwrap().fenced());
    turn.context.namespace_uid = "other-namespace".into();
    assert!(matches!(
        turn.lookup(&journal),
        Err(Error::Credential("AUTH_NAMESPACE_UID_MISMATCH"))
    ));
}

#[test]
fn observed_loss_of_private_directory_permissions_refuses() {
    let root = private_root();
    let journal = Journal::open(root.path(), 4).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        Fixture::named("direct-one-shot").claim(&journal),
        Err(Error::Unavailable)
    ));
}

#[test]
fn replay_without_durable_owner_cannot_create_a_record() {
    let root = private_root();
    let j = Journal::open(root.path(), 4).unwrap();
    let mut f = Fixture::named("direct-one-shot");
    f.context.seen_admission_jti = true;
    assert!(matches!(
        f.claim(&j),
        Err(Error::Credential("AUTH_CONTEXT_LOST"))
    ));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1); // lock only
}

#[test]
fn concurrent_delivery_publishes_one_fresh_claim() {
    let root = private_root();
    let j = Arc::new(Journal::open(root.path(), 4).unwrap());
    let threads: Vec<_> = (0..12)
        .map(|_| {
            let j = j.clone();
            std::thread::spawn(move || {
                let f = Fixture::named("direct-one-shot");
                for _ in 0..100 {
                    match f.claim(&j) {
                        Ok(Claim::Fresh(_)) => return true,
                        Ok(Claim::Recovery(_)) => return false,
                        Err(Error::Unavailable) => std::thread::sleep(Duration::from_millis(2)),
                        _ => panic!("unexpected admission refusal"),
                    }
                }
                panic!("admission remained busy")
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum::<usize>(),
        1
    );
}

#[test]
fn enduring_turns_keep_original_owner_and_count_initial_task() {
    let root = private_root();
    let j = Journal::open(root.path(), 20).unwrap();
    let first = fresh(Fixture::named("parent-create").claim(&j).unwrap());
    assert!(matches!(
        Fixture::turn("turn-1").claim(&j),
        Err(Error::Busy)
    ));
    j.finish(&first, receipt()).unwrap();
    let turn = fresh(Fixture::turn("turn-1").claim(&j).unwrap());
    assert!(matches!(
        Fixture::turn("turn-2").claim(&j),
        Err(Error::Busy)
    ));
    j.finish(&turn, receipt()).unwrap();
    for id in ["turn-2", "turn-3"] {
        let turn = fresh(Fixture::turn(id).claim(&j).unwrap());
        j.finish(&turn, receipt()).unwrap();
    }
    assert!(matches!(
        Fixture::turn("turn-4").claim(&j),
        Err(Error::BudgetExhausted)
    ));
    j.finish(&first, receipt()).unwrap(); // root counter updates do not break completion idempotency
    let restarted = Journal::open(root.path(), 20).unwrap();
    assert!(matches!(
        Fixture::turn("turn-4").claim(&restarted),
        Err(Error::Credential("AUTH_CONTEXT_LOST"))
    ));
}

#[test]
fn incomplete_child_publication_is_uncertain_not_a_retry() {
    let root = private_root();
    let j = Journal::open(root.path(), 20).unwrap();
    let first = fresh(Fixture::named("parent-create").claim(&j).unwrap());
    j.finish(&first, receipt()).unwrap();
    let turn = Fixture::turn("turn-1");
    let child = fresh(turn.claim(&j).unwrap());
    // Equivalent persisted state to a crash after the parent fence but before
    // child publication. No native launch or real crash is claimed by this test.
    fs::remove_file(j.path(&child.record.scope)).unwrap();
    assert!(matches!(
        turn.claim(&j),
        Err(Error::Credential("AUTH_CONTEXT_LOST"))
    ));
}

#[test]
fn private_inode_pinning_and_nonregular_records_fail_closed() {
    let work = tempfile::tempdir().unwrap();
    let root = work.path().join("journal");
    let j = Journal::open(&root, 4).unwrap();
    fs::rename(&root, work.path().join("original")).unwrap();
    fs::create_dir(&root).unwrap();
    let f = Fixture::named("direct-one-shot");
    let ticket = fresh(f.claim(&j).unwrap());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_file(j.path(&ticket.record.scope)).unwrap();
    symlink("/dev/zero", j.path(&ticket.record.scope)).unwrap();
    assert!(matches!(f.claim(&j), Err(Error::Unavailable)));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(Journal::open(&root, 4), Err(Error::Unavailable)));
}
