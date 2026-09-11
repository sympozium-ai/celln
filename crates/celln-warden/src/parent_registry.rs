//! Caller-scoped live-owner routing. Authentication and durable permit claims
//! precede this boundary; a caller string from an HTTP body is NOT authentication.
//! Entries are never replaced, including after owner loss. Durable tombstones
//! additionally prevent replay across registry/process restarts.
use crate::parent_owner::{OwnerStatus, ParentOwner};
use celln_manifest::Hash;
use std::{
    collections::BTreeMap,
    sync::{mpsc, Mutex},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Initializing,
    Ready,
    TurnActive,
    ContextLost,
    Stopping,
    Stopped,
    TeardownUncertain,
}

struct Entry {
    principal: String,
    owner: Option<ParentOwner>,
    status: Status,
    reserved_bytes: u64,
}
struct State {
    entries: BTreeMap<String, Entry>,
    reserved_bytes: u64,
    draining: bool,
}
pub struct ParentRegistry {
    state: Mutex<State>,
    max_entries: usize,
    memory_bytes: u64,
}

/// Includes stopping and teardown-uncertain owners until a confirmed join.
#[derive(Debug, PartialEq, Eq)]
pub struct ReservedCapacity {
    pub owners: u32,
    pub memory_bytes: u64,
}

impl ParentRegistry {
    /// Join only already-finished owners. Never cancel live work or wait for
    /// an active handler. Keep identities and context-loss status after release;
    /// a reclaimed reservation is not permission to recreate this incarnation.
    pub fn reap_finished(&self) -> Result<usize, String> {
        let finished = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "parent registry unavailable")?;
            state
                .entries
                .iter_mut()
                .filter_map(|(id, entry)| {
                    if entry.owner.as_ref().is_some_and(ParentOwner::is_finished) {
                        entry.status = Status::Stopping;
                        Some((id.clone(), entry.owner.take().unwrap()))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        let mut released = 0;
        for (id, owner) in finished {
            // Even an observed thread exit is not a successful join: panic
            // remains teardown-uncertain and conservatively charged.
            let joined = owner.stop_and_join().is_ok();
            let mut state = self
                .state
                .lock()
                .map_err(|_| "parent registry unavailable")?;
            let entry = state.entries.get_mut(&id).unwrap();
            if joined {
                entry.status = Status::ContextLost;
                let bytes = std::mem::take(&mut entry.reserved_bytes);
                state.reserved_bytes -= bytes;
                released += 1;
            } else {
                entry.status = Status::TeardownUncertain;
            }
        }
        Ok(released)
    }

    pub fn reserved_capacity(&self) -> Result<ReservedCapacity, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "parent registry unavailable")?;
        Ok(ReservedCapacity {
            owners: state
                .entries
                .values()
                .filter(|entry| entry.reserved_bytes != 0)
                .count() as u32,
            memory_bytes: state.reserved_bytes,
        })
    }
    /// Budget must include parent, child and retained warm-mote memory as
    /// measured/accounted by the serving layer. This is logical reservation,
    /// not a claim about physical residency or a hardware RAM limit.
    pub fn new(max_entries: usize, memory_bytes: u64) -> Result<Self, String> {
        if !(1..=1024).contains(&max_entries) || memory_bytes == 0 {
            return Err("invalid parent registry capacity".into());
        }
        Ok(Self {
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                reserved_bytes: 0,
                draining: false,
            }),
            max_entries,
            memory_bytes,
        })
    }

    /// Call only after independent admission and durable incarnation claim.
    /// Initialization runs on the owner thread, not under the registry lock.
    /// A failed initialization keeps its identity occupied; it cannot be retried.
    pub fn spawn_admitted<F, H>(
        &self,
        principal: &str,
        incarnation: &Hash,
        lifetime: Duration,
        reserved_bytes: u64,
        initialize: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Result<H, String> + Send + 'static,
        H: FnMut(&[u8]) -> Result<Vec<u8>, String> + 'static,
    {
        self.insert_admitted(principal, incarnation, reserved_bytes, || {
            ParentOwner::spawn(lifetime, initialize)
        })
    }

    /// Native runtimes explicitly opt in to exact child cancellation. Legacy
    /// owners keep their existing contract and cannot masquerade as supporting it.
    pub fn spawn_admitted_with_children<F, H>(
        &self,
        principal: &str,
        incarnation: &Hash,
        lifetime: Duration,
        reserved_bytes: u64,
        initialize: F,
    ) -> Result<(), String>
    where
        F: FnOnce(
                std::sync::Arc<crate::parent_child_control::ChildControlSlot>,
            ) -> Result<H, String>
            + Send
            + 'static,
        H: FnMut(&[u8]) -> Result<Vec<u8>, String> + 'static,
    {
        self.insert_admitted(principal, incarnation, reserved_bytes, || {
            ParentOwner::spawn_with_children(incarnation.clone(), lifetime, initialize)
        })
    }

    fn insert_admitted(
        &self,
        principal: &str,
        incarnation: &Hash,
        reserved_bytes: u64,
        spawn: impl FnOnce() -> std::io::Result<ParentOwner>,
    ) -> Result<(), String> {
        if principal.is_empty() || principal.len() > 512 || reserved_bytes == 0 {
            return Err("invalid admitted owner binding".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "parent registry unavailable")?;
        if state.draining {
            return Err("parent owner is draining".into());
        }
        if state.entries.contains_key(&incarnation.0) {
            return Err("parent incarnation already claimed; reconcile original owner".into());
        }
        let total = state
            .reserved_bytes
            .checked_add(reserved_bytes)
            .ok_or("parent memory capacity exhausted")?;
        if state.entries.len() >= self.max_entries || total > self.memory_bytes {
            return Err("parent registry capacity exhausted".into());
        }
        let owner = spawn().map_err(|e| e.to_string())?;
        state.reserved_bytes = total;
        state.entries.insert(
            incarnation.0.clone(),
            Entry {
                principal: principal.into(),
                owner: Some(owner),
                status: Status::Initializing,
                reserved_bytes,
            },
        );
        Ok(())
    }

    pub fn submit(
        &self,
        principal: &str,
        incarnation: &Hash,
        bytes: &[u8],
    ) -> Result<mpsc::Receiver<Result<Vec<u8>, String>>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "parent registry unavailable")?;
        let entry = scoped(&state, principal, incarnation)?;
        if state.draining {
            return Err("parent owner is draining".into());
        }
        entry
            .owner
            .as_ref()
            .ok_or("parent owner unavailable; context lost")?
            .submit(bytes)
    }

    pub fn status(&self, principal: &str, incarnation: &Hash) -> Result<Status, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "parent registry unavailable")?;
        let entry = scoped(&state, principal, incarnation)?;
        Ok(match entry.owner.as_ref().map(ParentOwner::status) {
            Some(OwnerStatus::Initializing) => Status::Initializing,
            Some(OwnerStatus::Ready) => Status::Ready,
            Some(OwnerStatus::TurnActive) => Status::TurnActive,
            Some(OwnerStatus::Stopping) => Status::Stopping,
            Some(OwnerStatus::ContextLost) => Status::ContextLost,
            None => entry.status,
        })
    }

    /// Request cancellation only. Resources remain charged until stop joins.
    pub fn cancel(&self, principal: &str, incarnation: &Hash) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "parent registry unavailable")?;
        let entry = scoped(&state, principal, incarnation)?;
        if let Some(owner) = &entry.owner {
            owner.cancel();
        }
        Ok(())
    }

    /// Signal a caller-scoped exact child without waiting on its running handler.
    /// Parent ownership and capacity remain charged; this is not joined teardown.
    pub fn cancel_child(
        &self,
        principal: &str,
        identity: &crate::parent_child_control::Identity,
    ) -> Result<(), String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "parent registry unavailable")?;
        let entry = scoped(&state, principal, &identity.parent)?;
        entry
            .owner
            .as_ref()
            .ok_or("original parent owner unavailable")?
            .cancel_child(identity)
    }

    /// Cancellation + confirmed join, without holding the registry lock across
    /// guest teardown. Concurrent stop observes Stopping, never false success.
    /// A panicked owner remains conservatively charged as teardown uncertain.
    /// Atomically close admission, signal all live trees, then join each owner.
    /// Keep every identity/tombstone and report uncertain teardown as failure.
    pub fn drain(&self) -> Result<(), String> {
        let owners = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "parent registry unavailable")?;
            state.draining = true;
            state
                .entries
                .iter()
                .map(|(id, entry)| {
                    if let Some(owner) = &entry.owner {
                        owner.cancel();
                    }
                    (entry.principal.clone(), Hash(id.clone()))
                })
                .collect::<Vec<_>>()
        };
        let mut uncertain = false;
        for (principal, id) in owners {
            uncertain |= self.stop(&principal, &id).is_err();
        }
        if uncertain {
            Err("parent drain teardown uncertain".into())
        } else {
            Ok(())
        }
    }

    pub fn is_draining(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.draining)
            .unwrap_or(true)
    }

    pub fn stop(&self, principal: &str, incarnation: &Hash) -> Result<(), String> {
        let owner = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "parent registry unavailable")?;
            scoped(&state, principal, incarnation)?;
            let entry = state.entries.get_mut(&incarnation.0).unwrap();
            if entry.status == Status::Stopped
                || (entry.status == Status::ContextLost && entry.reserved_bytes == 0)
            {
                return Ok(());
            }
            let owner = entry
                .owner
                .take()
                .ok_or("parent teardown pending or uncertain")?;
            entry.status = Status::Stopping;
            owner
        };
        let result = owner.stop_and_join();
        let mut state = self
            .state
            .lock()
            .map_err(|_| "parent registry unavailable")?;
        let entry = state.entries.get_mut(&incarnation.0).unwrap();
        if result.is_ok() {
            entry.status = Status::Stopped;
            let released = std::mem::take(&mut entry.reserved_bytes);
            state.reserved_bytes -= released;
        } else {
            entry.status = Status::TeardownUncertain;
        }
        result
    }
}

fn scoped<'a>(state: &'a State, principal: &str, incarnation: &Hash) -> Result<&'a Entry, String> {
    state
        .entries
        .get(&incarnation.0)
        .filter(|e| e.principal == principal)
        .ok_or_else(|| "parent owner not found".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spawn(registry: &ParentRegistry, id: &Hash) -> Result<(), String> {
        registry.spawn_admitted("tenant-one", id, Duration::from_secs(10), 100, || {
            Ok(|bytes: &[u8]| Ok(bytes.to_vec()))
        })
    }
    #[test]
    fn drain_joins_all_owners_and_permanently_closes_admission() {
        let registry = ParentRegistry::new(4, 400).unwrap();
        let first = Hash::of(b"drain-one");
        let second = Hash::of(b"drain-two");
        spawn(&registry, &first).unwrap();
        spawn(&registry, &second).unwrap();
        registry.drain().unwrap();
        assert!(registry.is_draining());
        assert_eq!(registry.reserved_capacity().unwrap().owners, 0);
        assert_eq!(
            registry.status("tenant-one", &first).unwrap(),
            Status::Stopped
        );
        assert_eq!(
            registry.status("tenant-one", &second).unwrap(),
            Status::Stopped
        );
        assert!(spawn(&registry, &Hash::of(b"after-drain")).is_err());
        assert!(registry
            .submit("tenant-one", &first, b"no more work")
            .is_err());
        registry.drain().unwrap();
    }
    #[test]
    fn tenant_scope_applies_to_submit_status_and_stop() {
        let registry = ParentRegistry::new(4, 200).unwrap();
        let id = Hash::of(b"one");
        spawn(&registry, &id).unwrap();
        assert!(registry.submit("tenant-two", &id, b"input").is_err());
        assert!(registry.stop("tenant-two", &id).is_err());
        assert!(registry.cancel("tenant-two", &id).is_err());
        assert_eq!(
            registry.status("tenant-two", &id).unwrap_err(),
            registry
                .status("tenant-two", &Hash::of(b"missing"))
                .unwrap_err()
        );
        let response = registry.submit("tenant-one", &id, b"input").unwrap();
        assert_eq!(
            response
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            b"input"
        );
        registry.stop("tenant-one", &id).unwrap();
        assert_eq!(registry.status("tenant-one", &id).unwrap(), Status::Stopped);
        assert!(spawn(&registry, &id).is_err());
        registry.stop("tenant-one", &id).unwrap();
    }
    #[test]
    fn capacity_is_retained_until_join_and_identity_never_reused() {
        let registry = ParentRegistry::new(2, 100).unwrap();
        let one = Hash::of(b"one");
        let two = Hash::of(b"two");
        spawn(&registry, &one).unwrap();
        assert!(spawn(&registry, &two).is_err());
        registry.stop("tenant-one", &one).unwrap();
        spawn(&registry, &two).unwrap();
        registry.stop("tenant-one", &two).unwrap();
        assert!(spawn(&registry, &Hash::of(b"three")).is_err());
    }
    #[test]
    fn reaping_releases_expired_owner_but_preserves_context_loss_and_identity() {
        let registry = ParentRegistry::new(3, 200).unwrap();
        let expired = Hash::of(b"expired");
        let live = Hash::of(b"live");
        registry
            .spawn_admitted(
                "tenant-one",
                &expired,
                Duration::from_millis(20),
                100,
                || Ok(|bytes: &[u8]| Ok(bytes.to_vec())),
            )
            .unwrap();
        spawn(&registry, &live).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while registry.reap_finished().unwrap() == 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            registry.status("tenant-one", &expired).unwrap(),
            Status::ContextLost
        );
        assert_eq!(
            registry.reserved_capacity().unwrap(),
            ReservedCapacity {
                owners: 1,
                memory_bytes: 100
            }
        );
        assert!(registry.submit("tenant-one", &expired, b"retry").is_err());
        assert!(spawn(&registry, &expired).is_err());
        assert!(registry.status("tenant-two", &expired).is_err());
        registry.stop("tenant-one", &expired).unwrap();
        assert_eq!(
            registry.status("tenant-one", &expired).unwrap(),
            Status::ContextLost
        );
        assert_eq!(registry.reap_finished().unwrap(), 0);
        assert_eq!(
            registry
                .submit("tenant-one", &live, b"still alive")
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
                .unwrap(),
            b"still alive"
        );
        registry.stop("tenant-one", &live).unwrap();
    }

    #[test]
    fn reaping_panicked_owner_never_releases_capacity() {
        let registry = ParentRegistry::new(2, 100).unwrap();
        let id = Hash::of(b"reap-panic");
        registry
            .spawn_admitted("tenant-one", &id, Duration::from_secs(10), 100, || {
                Ok(|_: &[u8]| -> Result<Vec<u8>, String> { panic!("test panic") })
            })
            .unwrap();
        assert!(registry
            .submit("tenant-one", &id, b"panic")
            .unwrap()
            .recv_timeout(Duration::from_secs(2))
            .is_err());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            assert_eq!(registry.reap_finished().unwrap(), 0);
            if registry.status("tenant-one", &id).unwrap() == Status::TeardownUncertain {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert_eq!(
            registry.reserved_capacity().unwrap(),
            ReservedCapacity {
                owners: 1,
                memory_bytes: 100
            }
        );
        assert!(registry.stop("tenant-one", &id).is_err());
        assert!(spawn(&registry, &Hash::of(b"replacement")).is_err());
    }
    #[test]
    fn failed_owner_reports_context_loss_and_panicked_join_retains_capacity() {
        let registry = ParentRegistry::new(2, 100).unwrap();
        let id = Hash::of(b"panic");
        registry
            .spawn_admitted("tenant-one", &id, Duration::from_secs(10), 100, || {
                Ok(|_: &[u8]| -> Result<Vec<u8>, String> { panic!("test owner panic") })
            })
            .unwrap();
        let response = registry.submit("tenant-one", &id, b"input").unwrap();
        assert!(response.recv_timeout(Duration::from_secs(2)).is_err());
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while registry.status("tenant-one", &id).unwrap() != Status::ContextLost {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(registry.stop("tenant-one", &id).is_err());
        assert_eq!(
            registry.status("tenant-one", &id).unwrap(),
            Status::TeardownUncertain
        );
        assert_eq!(
            registry.reserved_capacity().unwrap(),
            ReservedCapacity {
                owners: 1,
                memory_bytes: 100
            }
        );
        assert!(spawn(&registry, &Hash::of(b"new")).is_err());
        assert!(spawn(&registry, &id).is_err());
    }
    #[test]
    fn teardown_does_not_lock_other_owners_and_stop_is_not_early_success() {
        let registry = std::sync::Arc::new(ParentRegistry::new(3, 300).unwrap());
        let one = Hash::of(b"one");
        let two = Hash::of(b"two");
        let (started, ready) = mpsc::sync_channel(1);
        let (release, wait) = mpsc::sync_channel(1);
        registry
            .spawn_admitted(
                "tenant-one",
                &one,
                Duration::from_secs(10),
                100,
                move || {
                    Ok(move |_: &[u8]| {
                        started.send(()).unwrap();
                        wait.recv().unwrap();
                        Ok(vec![1])
                    })
                },
            )
            .unwrap();
        let reply = registry.submit("tenant-one", &one, b"input").unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let other = registry.clone();
        let stop_id = one.clone();
        let stopper = std::thread::spawn(move || other.stop("tenant-one", &stop_id));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while registry.status("tenant-one", &one).unwrap() != Status::Stopping {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(registry.stop("tenant-one", &one).is_err());
        spawn(&registry, &two).unwrap();
        registry.stop("tenant-one", &two).unwrap();
        release.send(()).unwrap();
        stopper.join().unwrap().unwrap();
        assert!(reply.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
    }

    #[test]
    fn scoped_child_cancel_routes_while_handler_runs_and_never_retargets() {
        // Real owner thread/control routing, synthetic worker: no VM guarantee.
        use crate::{
            parent_lease::{ReservedTurn, TurnLimits},
            parent_protocol::TurnRequest,
        };
        let registry = ParentRegistry::new(2, 8192).unwrap();
        let parent = Hash::of(b"scoped-parent");
        let bound = parent.clone();
        let (entered, ready) = mpsc::sync_channel(1);
        registry
            .spawn_admitted_with_children(
                "tenant",
                &parent,
                Duration::from_secs(30),
                4096,
                move |children| {
                    Ok(move |bytes: &[u8]| {
                        let turn = String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())?;
                        let reserved = ReservedTurn {
                            parent: bound.clone(),
                            child: Hash::of(&serde_json::to_vec(&(&bound.0, &turn)).unwrap()),
                            request: TurnRequest {
                                api_version: crate::parent_protocol::VERSION.into(),
                                turn_id: turn,
                                task: "data".into(),
                            },
                            limits: TurnLimits {
                                memory_bytes: 4096,
                                timeout: Duration::from_secs(5),
                                model_requests: 0,
                                output_tokens: 0,
                            },
                        };
                        let (identity, child) = children.register(&reserved)?;
                        entered.send(identity.clone()).map_err(|e| e.to_string())?;
                        child.scope(|| {
                            while celln_control::check().is_ok() {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                        });
                        celln_control::check().map_err(|e| e.to_string())?;
                        children.retire(&identity)?;
                        Ok(b"cancelled-child-only".to_vec())
                    })
                },
            )
            .unwrap();
        let first = registry.submit("tenant", &parent, b"first").unwrap();
        let old = ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(registry.cancel_child("other-tenant", &old).is_err());
        assert_eq!(
            registry.status("tenant", &parent).unwrap(),
            Status::TurnActive
        );
        registry.cancel_child("tenant", &old).unwrap();
        assert_eq!(
            first.recv_timeout(Duration::from_secs(2)).unwrap().unwrap(),
            b"cancelled-child-only"
        );
        assert_eq!(registry.status("tenant", &parent).unwrap(), Status::Ready);
        assert_eq!(registry.reserved_capacity().unwrap().memory_bytes, 4096);
        let second = registry.submit("tenant", &parent, b"second").unwrap();
        let next = ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(registry.cancel_child("tenant", &old).is_err());
        assert_eq!(
            registry.status("tenant", &parent).unwrap(),
            Status::TurnActive
        );
        registry.cancel_child("tenant", &next).unwrap();
        assert!(second.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
        registry.stop("tenant", &parent).unwrap();
        assert!(registry.cancel_child("tenant", &next).is_err());
        assert_eq!(registry.reserved_capacity().unwrap().memory_bytes, 0);

        let legacy = Hash::of(b"legacy-parent");
        registry
            .spawn_admitted("tenant", &legacy, Duration::from_secs(30), 4096, || {
                Ok(|_: &[u8]| Ok(vec![]))
            })
            .unwrap();
        let mut unsupported = next;
        unsupported.parent = legacy.clone();
        assert!(registry.cancel_child("tenant", &unsupported).is_err());
        registry.stop("tenant", &legacy).unwrap();
    }
}
