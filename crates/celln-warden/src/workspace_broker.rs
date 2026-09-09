//! Run-owned data over the existing bounded broker channel, never a host mount.
//! Only host admission can mint a grant. A guest cannot choose its parent or
//! child identity. Dropping the turn lease revokes every copy of that grant.
use crate::parent_lease::ReservedTurn;
use celln_control::Control;
use celln_manifest::Hash;
use celln_store::workspace::{Limits, Workspace};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, Weak};

pub struct Owner {
    parent: Hash,
    data: Arc<Mutex<Workspace>>,
    claimed: BTreeSet<String>,
    active: Weak<Mutex<Authority>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(active) = self.active.upgrade() {
            if let Ok(mut authority) = active.lock() {
                authority.active = false;
            }
        }
    }
}

struct Authority {
    active: bool,
    remaining: usize,
    read: bool,
    write: bool,
    control: Control,
}

/// Host-only lease: keep alive until the child VM has been joined/destroyed.
/// Revocation itself does not constitute proof of VM teardown.
pub struct Lease(Arc<Mutex<Authority>>);
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut authority) = self.0.lock() {
            authority.active = false;
        }
    }
}

#[derive(Clone)]
pub struct Grant {
    parent: Hash,
    data: Arc<Mutex<Workspace>>,
    authority: Arc<Mutex<Authority>>,
}
impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkspaceGrant(<host-owned>)")
    }
}
impl PartialEq for Grant {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.authority, &other.authority)
    }
}
impl Eq for Grant {}

impl Owner {
    pub fn new(parent: Hash, limits: Limits) -> Result<Self, String> {
        let data = Workspace::new(parent.clone(), limits).map_err(|e| e.to_string())?;
        Ok(Self {
            parent,
            data: Arc::new(Mutex::new(data)),
            claimed: BTreeSet::new(),
            active: Weak::new(),
        })
    }

    /// Call only after independent admission and durable turn reservation.
    /// This binds existing authority; it does not establish admission by itself.
    pub fn begin(
        &mut self,
        turn: &ReservedTurn,
        read: bool,
        write: bool,
        max_operations: usize,
        control: Control,
    ) -> Result<(Lease, Grant), String> {
        let child = Hash::of(
            &serde_json::to_vec(&(&self.parent.0, &turn.request.turn_id))
                .map_err(|_| "invalid workspace child identity")?,
        );
        if turn.parent != self.parent
            || turn.child != child
            || (!read && !write)
            || !(1..=64).contains(&max_operations)
            || self.claimed.len() >= 1024
            || self.claimed.contains(&turn.child.0)
        {
            return Err("workspace grant does not match reserved child or bounds".into());
        }
        control.check().map_err(|e| e.to_string())?;
        if let Some(active) = self.active.upgrade() {
            if active
                .lock()
                .map_err(|_| "workspace authority unavailable")?
                .active
            {
                return Err("workspace already has an active child".into());
            }
        }
        self.claimed.insert(turn.child.0.clone());
        let authority = Arc::new(Mutex::new(Authority {
            active: true,
            remaining: max_operations,
            read,
            write,
            control,
        }));
        self.active = Arc::downgrade(&authority);
        Ok((
            Lease(authority.clone()),
            Grant {
                parent: self.parent.clone(),
                data: self.data.clone(),
                authority,
            },
        ))
    }
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
enum Operation {
    Read {
        name: String,
    },
    Write {
        name: String,
        revision: u64,
        content: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    api_version: String,
    body: Operation,
}

impl Grant {
    pub(crate) fn request(&self, raw: &str) -> Result<Vec<u8>, String> {
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| "workspace authority unavailable")?;
        authority.control.check().map_err(|e| e.to_string())?;
        if !authority.active || authority.remaining == 0 {
            return Err("workspace grant revoked or exhausted".into());
        }
        // Malformed and denied operations spend their grant budget too.
        authority.remaining -= 1;
        if raw.len() > 8192 {
            return Err("workspace request exceeds broker wire budget".into());
        }
        let request: Request =
            serde_json::from_str(raw).map_err(|_| "invalid workspace request")?;
        if request.api_version != "celln.workspace/v1" {
            return Err("unsupported workspace request version".into());
        }
        let mut data = self.data.lock().map_err(|_| "workspace unavailable")?;
        let response = match request.body {
            Operation::Read { name } if authority.read => {
                let bytes = data.read(&self.parent, &name).map_err(|e| e.to_string())?;
                let content = std::str::from_utf8(bytes).map_err(|_| "artifact is not text")?;
                serde_json::json!({"revision":data.revision(), "content":content})
            }
            Operation::Write {
                name,
                revision,
                content,
            } if authority.write => {
                let revision = data
                    .write(&self.parent, revision, &name, content.as_bytes())
                    .map_err(|e| e.to_string())?;
                serde_json::json!({"revision":revision})
            }
            _ => return Err("workspace operation not granted".into()),
        };
        serde_json::to_vec(&response).map_err(|_| "workspace response encoding failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::{HttpBroker, HttpPolicy};
    use crate::{parent_lease::TurnLimits, parent_protocol::TurnRequest};
    use serde_json::json;
    use std::time::Duration;

    fn turn(parent: &Hash, id: &str) -> ReservedTurn {
        ReservedTurn {
            parent: parent.clone(),
            child: Hash::of(&serde_json::to_vec(&(&parent.0, id)).unwrap()),
            request: TurnRequest {
                api_version: crate::parent_protocol::VERSION.into(),
                turn_id: id.into(),
                task: "test".into(),
            },
            limits: TurnLimits {
                memory_bytes: 4096,
                timeout: Duration::from_secs(30),
                model_requests: 1,
                output_tokens: 32,
            },
        }
    }
    fn control() -> Control {
        Control::new(Duration::from_secs(30)).unwrap()
    }
    fn owner(parent: &Hash) -> Owner {
        Owner::new(
            parent.clone(),
            Limits {
                files: 2,
                file_bytes: 16,
                total_bytes: 24,
            },
        )
        .unwrap()
    }
    fn wire(body: serde_json::Value) -> String {
        json!({"apiVersion":"celln.workspace/v1", "body":body}).to_string()
    }
    fn broker(grant: Grant) -> HttpBroker {
        let mut policy = HttpPolicy::new(vec![]);
        policy.workspace = Some(grant);
        HttpBroker::new(policy)
    }

    #[test]
    fn cross_turn_data_with_revocation_and_no_replay() {
        let parent = Hash::of(b"parent");
        let mut owner = owner(&parent);
        let first = turn(&parent, "one");
        let (lease, grant) = owner.begin(&first, true, true, 4, control()).unwrap();
        let mut first_broker = broker(grant);
        assert!(first_broker
            .fetch(&wire(
                json!({"operation":"write","name":"note.txt","revision":0,"content":"violet"})
            ))
            .is_ok());
        let second = turn(&parent, "two");
        assert!(owner.begin(&second, true, false, 4, control()).is_err());
        drop(lease);
        assert!(first_broker
            .fetch(&wire(json!({"operation":"read","name":"note.txt"})))
            .is_err());
        assert!(owner.begin(&first, true, true, 4, control()).is_err());
        let (_lease, grant) = owner.begin(&second, true, false, 4, control()).unwrap();
        let mut next = broker(grant);
        let value: serde_json::Value = serde_json::from_slice(
            &next
                .fetch(&wire(json!({"operation":"read","name":"note.txt"})))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value, json!({"revision":1,"content":"violet"}));
        assert!(next
            .fetch(&wire(
                json!({"operation":"write","name":"note.txt","revision":1,"content":"orange"})
            ))
            .is_err());
    }

    #[test]
    fn authority_is_explicit_bound_bounded_and_cancelled() {
        let parent = Hash::of(b"parent");
        let mut owner = owner(&parent);
        assert!(owner
            .begin(&turn(&Hash::of(b"other"), "one"), true, true, 4, control())
            .is_err());
        let mut forged = turn(&parent, "one");
        forged.child = Hash::of(b"forged");
        assert!(owner.begin(&forged, true, true, 4, control()).is_err());
        let read = wire(json!({"operation":"read","name":"note.txt"}));
        assert!(HttpBroker::new(HttpPolicy::new(vec![]))
            .fetch(&read)
            .is_err());
        let stop = control();
        let (_lease, grant) = owner
            .begin(&turn(&parent, "one"), true, true, 2, stop.clone())
            .unwrap();
        let mut active = broker(grant.clone());
        assert!(active
            .fetch(&wire(
                json!({"operation":"write","name":"note.txt","revision":0,"content":"violet"})
            ))
            .is_ok());
        stop.cancel();
        assert!(active.fetch(&read).is_err());
        assert!(broker(grant).fetch(&read).is_err());
    }

    #[test]
    fn malformed_requests_quota_and_stale_writes_do_not_mutate() {
        let parent = Hash::of(b"parent");
        let mut owner = owner(&parent);
        let (_lease, grant) = owner
            .begin(&turn(&parent, "one"), true, true, 10, control())
            .unwrap();
        let mut active = broker(grant);
        for body in [
            json!({"operation":"write","name":"../escape","revision":0,"content":"x"}),
            json!({"operation":"write","name":"note.txt","revision":0,"content":"too large for the quota"}),
            json!({"operation":"write","name":"note.txt","revision":0,"content":"x","parent":"other"}),
        ] {
            assert!(active.fetch(&wire(body)).is_err());
        }
        assert!(active
            .fetch(&wire(
                json!({"operation":"write","name":"note.txt","revision":0,"content":"violet"})
            ))
            .is_ok());
        assert!(active
            .fetch(&wire(
                json!({"operation":"write","name":"note.txt","revision":0,"content":"orange"})
            ))
            .is_err());
        let read = wire(json!({"operation":"read","name":"note.txt"}));
        for _ in 0..5 {
            assert!(active.fetch(&read).is_ok());
        }
        assert!(active.fetch(&read).is_err());
    }

    #[test]
    fn losing_parent_owner_revokes_even_a_retained_turn_lease() {
        let parent = Hash::of(b"parent");
        let mut owner = owner(&parent);
        let (_lease, grant) = owner
            .begin(&turn(&parent, "one"), true, true, 4, control())
            .unwrap();
        let mut broker = broker(grant);
        drop(owner);
        assert!(broker
            .fetch(&wire(
                json!({"operation":"write","name":"note.txt","revision":0,"content":"x"})
            ))
            .is_err());
    }
}
