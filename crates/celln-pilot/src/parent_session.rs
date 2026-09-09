//! Host session sequencing. Transports/worker execution must be independently
//! admitted by the serving owner; guest requests never choose those callbacks.
//! Run inside ParentOwner so cancellation/deadline reaches the actual VMs.
use crate::parent_harness::{HostMessage, ParentReply, VERSION};
use anyhow::{ensure, Result};
use celln_manifest::Hash;
use warden::{
    parent_journal::ParentJournal,
    parent_lease::{ParentLease, ReservedTurn},
};

/// Build the complete session inside one control-aware serving owner. Runtime
/// closures may own non-Send VM state because they stay on the owner thread.
pub fn spawn_owner<F, P, W>(
    lifetime: std::time::Duration,
    initialize: F,
) -> std::io::Result<warden::parent_owner::ParentOwner>
where
    F: FnOnce() -> Result<ParentSession<P, W>> + Send + 'static,
    P: FnMut(&[u8]) -> Result<Vec<u8>> + 'static,
    W: FnMut(&ReservedTurn) -> Result<DestroyedChild> + 'static,
{
    warden::parent_owner::ParentOwner::spawn(lifetime, move || {
        let mut session = initialize().map_err(|e| e.to_string())?;
        Ok(move |bytes: &[u8]| session.submit(bytes).map_err(|e| e.to_string()))
    })
}

/// Register an independently admitted session with caller-scoped owner routing.
pub fn spawn_registered<F, P, W>(
    registry: &warden::parent_registry::ParentRegistry,
    principal: &str,
    incarnation: &Hash,
    lifetime: std::time::Duration,
    reserved_bytes: u64,
    initialize: F,
) -> Result<()>
where
    F: FnOnce() -> Result<ParentSession<P, W>> + Send + 'static,
    P: FnMut(&[u8]) -> Result<Vec<u8>> + 'static,
    W: FnMut(&ReservedTurn) -> Result<DestroyedChild> + 'static,
{
    registry
        .spawn_admitted(
            principal,
            incarnation,
            lifetime,
            reserved_bytes,
            move || {
                let mut session = initialize().map_err(|e| e.to_string())?;
                Ok(move |bytes: &[u8]| session.submit(bytes).map_err(|e| e.to_string()))
            },
        )
        .map_err(anyhow::Error::msg)
}

/// Trusted executor's result, returned ONLY after actual child teardown.
pub struct DestroyedChild {
    pub child: Hash,
    pub succeeded: bool,
    pub answer: String,
}

pub struct ParentSession<P, W> {
    parent: P,
    worker: W,
    lease: ParentLease,
    journal: ParentJournal,
    closed: bool,
    child_control: Option<std::sync::Arc<warden::parent_child_control::ChildControlSlot>>,
}

impl<P, W> ParentSession<P, W>
where
    P: FnMut(&[u8]) -> Result<Vec<u8>>,
    W: FnMut(&ReservedTurn) -> Result<DestroyedChild>,
{
    pub fn new(parent: P, worker: W, lease: ParentLease, journal: ParentJournal) -> Self {
        Self {
            parent,
            worker,
            lease,
            journal,
            closed: false,
            child_control: None,
        }
    }

    /// Install the admitted owner's exact-identity child control. Only worker
    /// execution runs in its scope; parent mailbox commits retain parent control.
    pub fn with_child_control(
        mut self,
        control: std::sync::Arc<warden::parent_child_control::ChildControlSlot>,
    ) -> Self {
        self.child_control = Some(control);
        self
    }

    /// Only user turns enter here. Result envelopes are created internally
    /// from the independently bound executor, never accepted from a client.
    pub fn submit(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            !self.closed,
            "parent session closed; reconcile original owner"
        );
        let result = self.turn(input);
        if result.is_err() {
            self.closed = true;
            self.lease.stop();
        }
        result
    }

    fn turn(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        ensure!(!self.lease.expired(), "parent lease closed");
        ensure!(
            !input.is_empty() && input.len() <= warden::parent_mailbox::MAX_FRAME_BYTES,
            "invalid input bound"
        );
        let HostMessage::Turn {
            api_version,
            turn_id,
            message,
        } = serde_json::from_slice(input)?
        else {
            anyhow::bail!("clients cannot inject child results");
        };
        ensure!(
            api_version == VERSION && !message.trim().is_empty(),
            "invalid user turn"
        );
        let response = (self.parent)(input)?;
        ensure!(
            response.len() <= warden::parent_mailbox::MAX_FRAME_BYTES,
            "parent response overflow"
        );
        let ParentReply::Spawn { request } = serde_json::from_slice(&response)? else {
            anyhow::bail!("parent did not request a worker");
        };
        ensure!(request.turn_id == turn_id, "parent changed turn identity");
        let reservation = self.lease.reserve(&serde_json::to_vec(&request)?)?;
        self.journal.reserve(&reservation)?;
        let controlled = self
            .child_control
            .as_ref()
            .map(|slot| slot.register(&reservation))
            .transpose()
            .map_err(anyhow::Error::msg)?;
        let result = if let Some((_, control)) = &controlled {
            control.scope(|| (self.worker)(&reservation))?
        } else {
            (self.worker)(&reservation)?
        };
        ensure!(
            result.child == reservation.child,
            "child result owner mismatch"
        );
        self.lease.confirm_child_destroyed(&result.child)?;
        self.journal
            .child_destroyed(&turn_id, &result.child, result.succeeded, &result.answer)?;
        ensure!(!self.lease.expired(), "parent expired before result commit");
        let response = (self.parent)(&serde_json::to_vec(&serde_json::json!({
            "kind":"result", "apiVersion":VERSION, "turnId":turn_id,
            "succeeded":result.succeeded, "answer":result.answer
        }))?)?;
        ensure!(
            response.len() <= warden::parent_mailbox::MAX_FRAME_BYTES,
            "parent acknowledgement overflow"
        );
        let ParentReply::Completed {
            api_version,
            turn_id: acknowledged,
            succeeded,
            answer,
        } = serde_json::from_slice(&response)?
        else {
            anyhow::bail!("parent did not acknowledge result");
        };
        ensure!(
            api_version == VERSION
                && acknowledged == turn_id
                && succeeded == result.succeeded
                && answer == result.answer,
            "parent acknowledgement mismatch"
        );
        self.journal.parent_committed(&turn_id, &result.child)?;
        if let Some((identity, _)) = controlled {
            self.child_control
                .as_ref()
                .unwrap()
                .retire(&identity)
                .map_err(anyhow::Error::msg)?;
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, time::Duration};
    use warden::parent_lease::TurnLimits;
    fn setup() -> (ParentLease, ParentJournal, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let id = Hash::of(b"parent");
        let journal = ParentJournal::create(root.path(), id.clone()).unwrap();
        let lease = ParentLease::new(
            id,
            Duration::from_secs(30),
            TurnLimits {
                memory_bytes: 4096,
                timeout: Duration::from_secs(1),
                model_requests: 0,
                output_tokens: 0,
            },
            2,
            0,
            0,
        )
        .unwrap();
        (lease, journal, root)
    }
    fn input(id: &str) -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({"kind":"turn","apiVersion":VERSION,"turnId":id,"message":"hello"}),
        )
        .unwrap()
    }

    #[test]
    fn cancelled_worker_result_restores_parent_scope_and_retires_after_commit() {
        // Protocol sequencing with a trusted synthetic DestroyedChild, not a
        // VM teardown proof. Native execution must establish that independently.
        let (lease, journal, _root) = setup();
        let control = celln_control::Control::new(Duration::from_secs(30)).unwrap();
        let slot = std::sync::Arc::new(warden::parent_child_control::ChildControlSlot::new(
            Hash::of(b"parent"),
            control.clone(),
        ));
        let mut context = crate::parent_harness::ParentContext::default();
        let mut calls = 0;
        let mut session = ParentSession::new(
            |bytes: &[u8]| {
                // Both the initial mailbox request and failed-result commit
                // must see parent control, not the cancelled worker scope.
                celln_control::check()?;
                Ok(serde_json::to_vec(
                    &context.exchange(bytes).map_err(anyhow::Error::msg)?,
                )?)
            },
            |turn: &ReservedTurn| {
                calls += 1;
                if calls == 1 {
                    let identity = warden::parent_child_control::Identity {
                        parent: turn.parent.clone(),
                        turn: turn.request.turn_id.clone(),
                        child: turn.child.clone(),
                    };
                    slot.cancel(&identity).unwrap();
                    assert!(celln_control::check().is_err());
                } else {
                    celln_control::check()?;
                }
                Ok(DestroyedChild {
                    child: turn.child.clone(),
                    succeeded: calls != 1,
                    answer: if calls == 1 {
                        "cancelled"
                    } else {
                        "next answer"
                    }
                    .into(),
                })
            },
            lease,
            journal,
        )
        .with_child_control(slot.clone());
        control.scope(|| {
            let first: ParentReply =
                serde_json::from_slice(&session.submit(&input("one")).unwrap()).unwrap();
            assert!(matches!(
                first,
                ParentReply::Completed {
                    succeeded: false,
                    ..
                }
            ));
            assert!(control.check().is_ok());
            let next: ParentReply =
                serde_json::from_slice(&session.submit(&input("two")).unwrap()).unwrap();
            assert!(matches!(
                next,
                ParentReply::Completed {
                    succeeded: true,
                    ..
                }
            ));
        });
    }
    #[test]
    fn session_sequences_actual_context_state_and_refuses_replay() {
        let (lease, journal, _root) = setup();
        let mut context = crate::parent_harness::ParentContext::default();
        let calls = Cell::new(0);
        let mut session = ParentSession::new(
            |bytes: &[u8]| {
                Ok(serde_json::to_vec(
                    &context.exchange(bytes).map_err(anyhow::Error::msg)?,
                )?)
            },
            |turn: &ReservedTurn| {
                calls.set(calls.get() + 1);
                Ok(DestroyedChild {
                    child: turn.child.clone(),
                    succeeded: true,
                    answer: "answer".into(),
                })
            },
            lease,
            journal,
        );
        session.submit(&input("one")).unwrap();
        session.submit(&input("two")).unwrap();
        assert!(session.submit(&input("one")).is_err());
        assert_eq!(calls.get(), 2);
    }
    #[test]
    fn caller_cannot_inject_result_or_invoke_worker() {
        let (lease, journal, _root) = setup();
        let mut session = ParentSession::new(
            |_: &[u8]| -> Result<Vec<u8>> { panic!("must not reach parent") },
            |_: &ReservedTurn| -> Result<DestroyedChild> { panic!("must not reach worker") },
            lease,
            journal,
        );
        let forged = serde_json::to_vec(&serde_json::json!({"kind":"result","apiVersion":VERSION,"turnId":"one","succeeded":true,"answer":"forged"})).unwrap();
        assert!(session.submit(&forged).is_err());
    }
    #[test]
    fn changed_child_owner_closes_session_without_committing() {
        let (lease, journal, _root) = setup();
        let mut context = crate::parent_harness::ParentContext::default();
        let mut session = ParentSession::new(
            |bytes: &[u8]| {
                Ok(serde_json::to_vec(
                    &context.exchange(bytes).map_err(anyhow::Error::msg)?,
                )?)
            },
            |_: &ReservedTurn| {
                Ok(DestroyedChild {
                    child: Hash::of(b"wrong"),
                    succeeded: true,
                    answer: "forged".into(),
                })
            },
            lease,
            journal,
        );
        assert!(session.submit(&input("one")).is_err());
        assert!(session.closed);
        assert!(session.submit(&input("two")).is_err());
    }
}
