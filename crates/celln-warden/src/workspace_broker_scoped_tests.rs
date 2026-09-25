use super::tests::{broker, control, owner, turn, wire};
use super::*;
use serde_json::json;

#[test]
fn scoped_artifacts_survive_three_children_but_not_parent_deletion() {
    let parent = Hash::of(b"cluster/namespace-uid/run-uid/incarnation");
    let mut store = owner(&parent);
    let write =
        wire(json!({"operation":"write","name":"notes/a.txt","revision":0,"content":"violet"}));
    let read = wire(json!({"operation":"read","name":"notes/a.txt"}));
    let mut stale = Vec::new();
    for id in ["initial", "second", "third"] {
        let (lease, grant) = store
            .begin_artifacts(&turn(&parent, id), true, true, 4, control())
            .unwrap();
        let mut transport = broker(grant);
        if id == "initial" {
            transport.fetch(&write).unwrap();
        }
        let reply: serde_json::Value =
            serde_json::from_slice(&transport.fetch(&read).unwrap()).unwrap();
        assert_eq!(reply, json!({"revision":1,"content":"violet"}));
        if id == "third" {
            // Parent deletion revokes even if its last lease is retained.
            drop(store);
            assert!(transport.fetch(&read).is_err());
            break;
        }
        drop(lease);
        assert!(transport.fetch(&read).is_err());
        stale.push(transport);
    }
    for mut transport in stale {
        assert!(transport.fetch(&read).is_err());
    }
    let other = Hash::of(b"cluster/namespace-uid/other-run/incarnation");
    let mut separate = owner(&other);
    let (_lease, grant) = separate
        .begin_artifacts(&turn(&other, "initial"), true, false, 1, control())
        .unwrap();
    assert!(broker(grant).fetch(&read).is_err());
}

#[test]
fn scoped_artifacts_refuse_extra_operations_paths_and_cancelled_custody() {
    let parent = Hash::of(b"parent");
    let mut owner = owner(&parent);
    let (_lease, grant) = owner
        .begin_artifacts(&turn(&parent, "one"), true, true, 32, control())
        .unwrap();
    let operation = control();
    grant.constrain(operation.clone()).unwrap();
    assert!(grant.constrain(control()).is_err());
    let mut transport = broker(grant);
    for name in [
        "../escape",
        "/etc/passwd",
        "a/../b",
        "a//b",
        "a\\b",
        "a/./b",
    ] {
        assert!(transport
            .fetch(&wire(
                json!({"operation":"write","name":name,"revision":0,"content":"no"})
            ))
            .is_err());
    }
    for body in [
        json!({"operation":"symlink","name":"a","target":"/etc/passwd"}),
        json!({"operation":"append","name":"a","revision":0,"content":"x"}),
        json!({"operation":"delete","name":"a","revision":0}),
        json!({"operation":"list"}),
        json!({"operation":"search","pattern":"a"}),
        json!({"operation":"write","name":"a","revision":0,"content":"x","parent":"foreign"}),
    ] {
        assert!(transport.fetch(&wire(body)).is_err());
    }
    transport
        .fetch(&wire(
            json!({"operation":"write","name":"a","revision":0,"content":"safe"}),
        ))
        .unwrap();
    operation.cancel();
    assert!(transport
        .fetch(&wire(json!({"operation":"read","name":"a"})))
        .is_err());
}

#[test]
fn scoped_artifact_caps_and_permissions_are_not_model_allowances() {
    let parent = Hash::of(b"parent");
    let mut owner = owner(&parent);
    assert!(owner
        .begin_artifacts(
            &turn(&Hash::of(b"foreign"), "one"),
            true,
            true,
            3,
            control()
        )
        .is_err());
    let (lease, grant) = owner
        .begin_artifacts(&turn(&parent, "one"), false, true, 3, control())
        .unwrap();
    let mut transport = broker(grant);
    assert!(transport
        .fetch(&wire(json!({"operation":"read","name":"a"})))
        .is_err());
    assert!(transport
        .fetch(&wire(
            json!({"operation":"write","name":"a","revision":0,"content":"x".repeat(17)})
        ))
        .is_err());
    transport
        .fetch(&wire(
            json!({"operation":"write","name":"a","revision":0,"content":"safe"}),
        ))
        .unwrap();
    assert_eq!(transport.used(), 0);
    assert!(transport
        .fetch(&wire(
            json!({"operation":"write","name":"a","revision":1,"content":"again"})
        ))
        .is_err());
    drop(lease);
    let (_lease, grant) = owner
        .begin_artifacts(&turn(&parent, "two"), true, false, 2, control())
        .unwrap();
    let mut transport = broker(grant);
    assert!(transport
        .fetch(&wire(
            json!({"operation":"write","name":"a","revision":1,"content":"no"})
        ))
        .is_err());
    let reply: serde_json::Value = serde_json::from_slice(
        &transport
            .fetch(&wire(json!({"operation":"read","name":"a"})))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(reply["content"], "safe");
}
