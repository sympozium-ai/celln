use super::tests::{broker, control, owner, turn, wire};
use super::*;
use serde_json::json;

fn rw(read: bool, write: bool) -> ArtifactOperations {
    ArtifactOperations::read_write(read, write)
}

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
            .begin_artifacts(&turn(&parent, id), rw(true, true), 4, control())
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
        .begin_artifacts(&turn(&other, "initial"), rw(true, false), 1, control())
        .unwrap();
    assert!(broker(grant).fetch(&read).is_err());
}

#[test]
fn scoped_artifacts_refuse_extra_operations_paths_and_cancelled_custody() {
    let parent = Hash::of(b"parent");
    let mut owner = owner(&parent);
    let (_lease, grant) = owner
        .begin_artifacts(&turn(&parent, "one"), rw(true, true), 32, control())
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
            rw(true, true),
            3,
            control()
        )
        .is_err());
    let (lease, grant) = owner
        .begin_artifacts(&turn(&parent, "one"), rw(false, true), 3, control())
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
        .begin_artifacts(&turn(&parent, "two"), rw(true, false), 2, control())
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

fn call(
    transport: &mut crate::egress::HttpBroker,
    body: serde_json::Value,
) -> Option<serde_json::Value> {
    transport
        .fetch(&wire(body))
        .ok()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn only(names: &[&str]) -> ArtifactOperations {
    let mut operations = ArtifactOperations::default();
    for name in names {
        assert!(operations.grant(name));
    }
    operations
}

#[test]
fn scoped_v2_grants_exactly_the_named_operations_across_owned_turns() {
    let parent = Hash::of(b"cluster/namespace-uid/run-uid/incarnation");
    let mut store = Owner::new(
        parent.clone(),
        celln_store::workspace::Limits {
            files: 4,
            file_bytes: 64,
            total_bytes: 256,
        },
    )
    .unwrap();
    // Turn one: append (an effect) creates data; nothing else is implied.
    let (lease, grant) = store
        .begin_artifacts(&turn(&parent, "one"), only(&["append"]), 8, control())
        .unwrap();
    let mut transport = broker(grant);
    assert_eq!(
        call(
            &mut transport,
            json!({"operation":"append","name":"log.txt","revision":0,"content":"red\n"})
        ),
        Some(json!({"revision":1}))
    );
    for body in [
        json!({"operation":"read","name":"log.txt"}),
        json!({"operation":"write","name":"log.txt","revision":1,"content":"x"}),
        json!({"operation":"list"}),
        json!({"operation":"search","pattern":"red"}),
        json!({"operation":"delete","name":"log.txt","revision":1}),
    ] {
        assert_eq!(call(&mut transport, body.clone()), None, "{body}");
    }
    drop(lease);
    // Turn two: list and search (no effect) see turn one's data; they never
    // imply read, and the revoked turn-one transport stays revoked.
    let (lease, grant) = store
        .begin_artifacts(
            &turn(&parent, "two"),
            only(&["list", "search"]),
            8,
            control(),
        )
        .unwrap();
    let mut reader = broker(grant);
    assert_eq!(
        call(&mut reader, json!({"operation":"list"})),
        Some(json!({"revision":1,"files":[{"name":"log.txt","bytes":4}]}))
    );
    assert_eq!(
        call(&mut reader, json!({"operation":"search","pattern":"re"})),
        Some(json!({"revision":1,"matches":[{"name":"log.txt","line":1,"text":"red"}]}))
    );
    assert_eq!(
        call(&mut reader, json!({"operation":"read","name":"log.txt"})),
        None
    );
    assert_eq!(
        call(
            &mut transport,
            json!({"operation":"append","name":"log.txt","revision":1,"content":"x"})
        ),
        None
    );
    drop(lease);
    // Turn three: delete only; a stale revision refuses without mutation.
    let (_lease, grant) = store
        .begin_artifacts(&turn(&parent, "three"), only(&["delete"]), 2, control())
        .unwrap();
    let mut deleter = broker(grant);
    assert_eq!(
        call(
            &mut deleter,
            json!({"operation":"delete","name":"log.txt","revision":0})
        ),
        None
    );
    assert_eq!(
        call(
            &mut deleter,
            json!({"operation":"delete","name":"log.txt","revision":1})
        ),
        Some(json!({"revision":2}))
    );
    // The aggregate operation cap counts refused calls too.
    assert_eq!(call(&mut deleter, json!({"operation":"list"})), None);
    // A different parent's owner never sees this parent's data.
    let other = Hash::of(b"cluster/namespace-uid/other-run/incarnation");
    let mut foreign = owner(&other);
    let (_lease, grant) = foreign
        .begin_artifacts(&turn(&other, "one"), only(&["list"]), 2, control())
        .unwrap();
    assert_eq!(
        call(&mut broker(grant), json!({"operation":"list"})),
        Some(json!({"revision":0,"files":[]}))
    );
    assert!(!ArtifactOperations::default().grant("symlink"));
}

#[test]
fn a_one_shot_store_is_private_to_its_grant_bounded_and_cancellable() {
    let run = Hash::of(b"one-shot-run");
    let limits = celln_store::workspace::Limits {
        files: 2,
        file_bytes: 16,
        total_bytes: 24,
    };
    assert!(Grant::ephemeral(
        run.clone(),
        limits,
        ArtifactOperations::default(),
        4,
        control()
    )
    .is_err());
    assert!(Grant::ephemeral(run.clone(), limits, only(&["read"]), 65, control()).is_err());
    let stop = control();
    let grant = Grant::ephemeral(
        run.clone(),
        limits,
        only(&["write", "read", "list"]),
        4,
        stop.clone(),
    )
    .unwrap();
    let mut transport = broker(grant);
    assert_eq!(
        call(
            &mut transport,
            json!({"operation":"write","name":"a.txt","revision":0,"content":"violet"})
        ),
        Some(json!({"revision":1}))
    );
    assert_eq!(
        call(&mut transport, json!({"operation":"read","name":"a.txt"})),
        Some(json!({"revision":1,"content":"violet"}))
    );
    assert_eq!(
        call(
            &mut transport,
            json!({"operation":"append","name":"a.txt","revision":1,"content":"x"})
        ),
        None
    );
    // Another one-shot grant for the same run identity is a new, empty store.
    let fresh = Grant::ephemeral(run, limits, only(&["list"]), 2, control()).unwrap();
    assert_eq!(
        call(&mut broker(fresh), json!({"operation":"list"})),
        Some(json!({"revision":0,"files":[]}))
    );
    stop.cancel();
    assert_eq!(call(&mut transport, json!({"operation":"list"})), None);
}
