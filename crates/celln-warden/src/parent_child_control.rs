//! Exact-identity cancellation rendezvous for an admitted parent's child.
//! Not admission, a durable journal, or proof of child teardown. The host owner
//! authenticates callers, reserves/persists the turn before registration, and
//! retains this slot until the actual child is joined and its result recorded.
use crate::{parent_lease::ReservedTurn, parent_protocol::TurnRequest};
use celln_control::Control;
use celln_manifest::Hash;
use std::{collections::BTreeSet, sync::Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub parent: Hash,
    pub turn: String,
    pub child: Hash,
}

struct Active {
    identity: Identity,
    control: Control,
}

#[derive(Default)]
struct State {
    active: Option<Active>,
    seen: BTreeSet<String>,
}

pub struct ChildControlSlot {
    parent: Hash,
    control: Control,
    state: Mutex<State>,
}

impl ChildControlSlot {
    pub fn new(parent: Hash, control: Control) -> Self {
        Self {
            parent,
            control,
            state: Mutex::new(State::default()),
        }
    }

    /// A registered identity is consumed for this owner even if work later
    /// fails. Registration never resets the ledger or revives an old turn.
    pub fn register(&self, turn: &ReservedTurn) -> Result<(Identity, Control), &'static str> {
        let encoded = serde_json::to_vec(&turn.request).map_err(|_| "invalid turn")?;
        TurnRequest::decode(&encoded).map_err(|_| "invalid turn")?;
        let child = Hash::of(
            &serde_json::to_vec(&(&self.parent.0, &turn.request.turn_id))
                .map_err(|_| "invalid identity")?,
        );
        if turn.parent != self.parent || turn.child != child || turn.limits.timeout.is_zero() {
            return Err("child control differs from reservation");
        }
        let mut state = self.state.lock().map_err(|_| "child control unavailable")?;
        self.control.check().map_err(|_| "parent stopped")?;
        if state.active.is_some()
            || state.seen.len() >= 1024
            || state.seen.contains(&turn.request.turn_id)
        {
            return Err("active, exhausted or repeated child identity");
        }
        let control = self
            .control
            .child(turn.limits.timeout)
            .map_err(|_| "invalid child lifetime")?;
        let identity = Identity {
            parent: self.parent.clone(),
            turn: turn.request.turn_id.clone(),
            child,
        };
        state.seen.insert(identity.turn.clone());
        state.active = Some(Active {
            identity: identity.clone(),
            control: control.clone(),
        });
        Ok((identity, control))
    }

    /// Signal only the exact registered child while holding the identity lock.
    /// Repeated exact cancellation is harmless; stale/mismatched requests never
    /// select another child. Success is NOT a teardown acknowledgement.
    pub fn cancel(&self, expected: &Identity) -> Result<(), &'static str> {
        let state = self.state.lock().map_err(|_| "child control unavailable")?;
        let active = state.active.as_ref().ok_or("no registered child")?;
        if active.identity != *expected {
            return Err("child identity mismatch");
        }
        active.control.cancel();
        Ok(())
    }

    /// Remove the rendezvous only after the caller has independently confirmed
    /// child teardown and recorded its outcome. This method frees no capacity,
    /// acknowledges no hardware property, and does not refund the seen identity.
    pub fn retire(&self, expected: &Identity) -> Result<(), &'static str> {
        let mut state = self.state.lock().map_err(|_| "child control unavailable")?;
        if !state
            .active
            .as_ref()
            .is_some_and(|active| active.identity == *expected)
        {
            return Err("child identity mismatch");
        }
        state.active = None;
        Ok(())
    }
}

impl Drop for ChildControlSlot {
    fn drop(&mut self) {
        // Exclusive destruction can still signal a poisoned slot's child.
        // Its owning worker must independently join; this is not teardown.
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(active) = &state.active {
            active.control.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parent_lease::TurnLimits;
    use std::{
        sync::{Arc, Barrier},
        time::Duration,
    };

    fn reservation(parent: &Hash, id: &str) -> ReservedTurn {
        ReservedTurn {
            parent: parent.clone(),
            child: Hash::of(&serde_json::to_vec(&(&parent.0, id)).unwrap()),
            request: TurnRequest {
                api_version: crate::parent_protocol::VERSION.into(),
                turn_id: id.into(),
                task: "data".into(),
            },
            limits: TurnLimits {
                memory_bytes: 4096,
                timeout: Duration::from_secs(30),
                model_requests: 1,
                output_tokens: 32,
            },
        }
    }

    #[test]
    fn exact_cancel_does_not_release_slot_refund_identity_or_stop_parent() {
        let parent = Hash::of(b"parent");
        let control = Control::new(Duration::from_secs(60)).unwrap();
        let slot = ChildControlSlot::new(parent.clone(), control.clone());
        let first = reservation(&parent, "first");
        let (id, child) = slot.register(&first).unwrap();
        slot.cancel(&id).unwrap();
        slot.cancel(&id).unwrap();
        assert!(child.check().is_err());
        assert!(control.check().is_ok());
        assert!(slot.register(&reservation(&parent, "next")).is_err());
        slot.retire(&id).unwrap();
        assert!(slot.register(&first).is_err());
        assert!(slot.cancel(&id).is_err());
        assert!(slot.register(&reservation(&parent, "next")).is_ok());
    }

    #[test]
    fn late_cancel_and_retire_cannot_touch_the_next_child() {
        let parent = Hash::of(b"parent");
        let slot = Arc::new(ChildControlSlot::new(
            parent.clone(),
            Control::new(Duration::from_secs(60)).unwrap(),
        ));
        let (old, _) = slot.register(&reservation(&parent, "old")).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let delayed = slot.clone();
        let wait = barrier.clone();
        let stale = old.clone();
        let caller = std::thread::spawn(move || {
            wait.wait();
            assert!(delayed.cancel(&stale).is_err());
            assert!(delayed.retire(&stale).is_err());
        });
        slot.retire(&old).unwrap();
        let (next, child) = slot.register(&reservation(&parent, "next")).unwrap();
        barrier.wait();
        caller.join().unwrap();
        assert!(child.check().is_ok());
        slot.cancel(&next).unwrap();
        assert!(child.check().is_err());
    }

    #[test]
    fn changed_bindings_and_stopped_parent_refuse_registration() {
        let parent = Hash::of(b"parent");
        let control = Control::new(Duration::from_secs(60)).unwrap();
        let slot = ChildControlSlot::new(parent.clone(), control.clone());
        assert!(slot
            .register(&reservation(&Hash::of(b"other"), "turn"))
            .is_err());
        let mut turn = reservation(&parent, "turn");
        turn.child = Hash::of(b"injected");
        assert!(slot.register(&turn).is_err());
        let (identity, child) = slot.register(&reservation(&parent, "turn")).unwrap();
        let mut wrong = identity.clone();
        wrong.parent = Hash::of(b"other");
        assert!(slot.cancel(&wrong).is_err());
        assert!(child.check().is_ok());
        control.cancel();
        assert!(child.check().is_err());
        slot.retire(&identity).unwrap();
        assert!(slot.register(&reservation(&parent, "next")).is_err());
    }

    #[test]
    fn losing_the_slot_signals_child_without_cancelling_parent() {
        let parent = Hash::of(b"parent");
        let control = Control::new(Duration::from_secs(60)).unwrap();
        let slot = ChildControlSlot::new(parent.clone(), control.clone());
        let (_, child) = slot.register(&reservation(&parent, "active")).unwrap();
        drop(slot);
        assert!(child.check().is_err());
        assert!(control.check().is_ok());
    }
}
