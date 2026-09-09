//! Host-owned, in-memory parent turn ledger. Not an admission decision or a
//! durable journal: the serving owner must persist reservations before spawn,
//! recheck signed grants, and enforce the returned ceilings on the real child.
//! A lost owner means context loss, never reconstruction of an empty ledger.

use crate::parent_protocol::TurnRequest;
use celln_manifest::Hash;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Fixed host-approved ceilings, reserved in full before each child launch.
#[derive(Clone, Copy, Debug)]
pub struct TurnLimits {
    pub memory_bytes: u64,
    pub timeout: Duration,
    pub model_requests: u64,
    pub output_tokens: u64,
}

#[derive(Debug)]
pub struct ReservedTurn {
    pub parent: Hash,
    pub child: Hash,
    pub request: TurnRequest,
    pub limits: TurnLimits,
}

pub struct ParentLease {
    parent: Hash,
    deadline: Instant,
    limits: TurnLimits,
    turns_left: usize,
    requests_left: u64,
    tokens_left: u64,
    seen: BTreeSet<String>,
    active: Option<Hash>,
    stopped: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LeaseError {
    #[error("invalid parent lease configuration")]
    Configuration,
    #[error("invalid turn envelope")]
    Protocol,
    #[error("parent is stopped or expired")]
    Stopped,
    #[error("turn identity already reserved; reconcile original owner")]
    Replay,
    #[error("another child still owns the active turn")]
    Busy,
    #[error("aggregate parent budget exhausted")]
    Budget,
    #[error("completion does not match the active child owner")]
    Owner,
}

impl ParentLease {
    /// `parent` must identify a freshly admitted process incarnation, not just
    /// a reusable Agent name. No guest field supplies this identity or limits.
    pub fn new(
        parent: Hash,
        lifetime: Duration,
        limits: TurnLimits,
        max_turns: usize,
        total_model_requests: u64,
        total_output_tokens: u64,
    ) -> Result<Self, LeaseError> {
        let deadline = Instant::now()
            .checked_add(lifetime)
            .ok_or(LeaseError::Configuration)?;
        if lifetime.is_zero()
            || limits.timeout.is_zero()
            || limits.memory_bytes == 0
            || !(1..=1024).contains(&max_turns)
            || (limits.model_requests == 0) != (limits.output_tokens == 0)
            || limits.model_requests > total_model_requests
            || limits.output_tokens > total_output_tokens
        {
            return Err(LeaseError::Configuration);
        }
        Ok(Self {
            parent,
            deadline,
            limits,
            turns_left: max_turns,
            requests_left: total_model_requests,
            tokens_left: total_output_tokens,
            seen: BTreeSet::new(),
            active: None,
            stopped: false,
        })
    }

    pub fn reserve(&mut self, bytes: &[u8]) -> Result<ReservedTurn, LeaseError> {
        self.reserve_at(bytes, Instant::now())
    }

    fn reserve_at(&mut self, bytes: &[u8], now: Instant) -> Result<ReservedTurn, LeaseError> {
        if now >= self.deadline {
            self.stopped = true;
        }
        if self.stopped {
            return Err(LeaseError::Stopped);
        }
        let request = TurnRequest::decode(bytes).map_err(|_| LeaseError::Protocol)?;
        if self.seen.contains(&request.turn_id) {
            return Err(LeaseError::Replay);
        }
        if self.active.is_some() {
            return Err(LeaseError::Busy);
        }
        if self.turns_left == 0
            || self.requests_left < self.limits.model_requests
            || self.tokens_left < self.limits.output_tokens
        {
            return Err(LeaseError::Budget);
        }
        // JSON tuple framing avoids delimiter collisions in the identity.
        let child = Hash::of(&serde_json::to_vec(&(&self.parent.0, &request.turn_id)).unwrap());
        self.turns_left -= 1;
        self.requests_left -= self.limits.model_requests;
        self.tokens_left -= self.limits.output_tokens;
        self.seen.insert(request.turn_id.clone());
        self.active = Some(child.clone());
        let mut limits = self.limits;
        limits.timeout = limits.timeout.min(self.deadline.duration_since(now));
        Ok(ReservedTurn {
            parent: self.parent.clone(),
            child,
            request,
            limits,
        })
    }

    /// Only call after the actual child owner confirms destruction. Failure,
    /// cancellation and uncertain model charges never refund a reservation.
    pub fn confirm_child_destroyed(&mut self, child: &Hash) -> Result<(), LeaseError> {
        if self.active.as_ref() != Some(child) {
            return Err(LeaseError::Owner);
        }
        self.active = None;
        Ok(())
    }

    /// Close admission immediately. Retain the active owner until confirmed
    /// destroyed; returning its identity is a cleanup instruction, not proof.
    pub fn stop(&mut self) -> Option<Hash> {
        self.stopped = true;
        self.active.clone()
    }

    /// The serving owner must drive this from its lease watchdog even while
    /// idle, and kill both VMs on expiry. Polling this ledger does not kill VMs.
    pub fn expired(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            self.stopped = true;
        }
        self.stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lease() -> ParentLease {
        ParentLease::new(
            Hash::of(b"parent-incarnation"),
            Duration::from_secs(60),
            TurnLimits {
                memory_bytes: 128 << 20,
                timeout: Duration::from_secs(30),
                model_requests: 3,
                output_tokens: 1536,
            },
            4,
            6,
            3072,
        )
        .unwrap()
    }
    fn request(id: &str) -> Vec<u8> {
        serde_json::to_vec(
            &serde_json::json!({"apiVersion":crate::parent_protocol::VERSION,
            "turnId":id,"task":"hello"}),
        )
        .unwrap()
    }
    fn error(result: Result<ReservedTurn, LeaseError>) -> LeaseError {
        result.unwrap_err()
    }

    #[test]
    fn serial_turns_bind_parent_child_and_never_replay() {
        let mut owner = lease();
        let first = owner.reserve(&request("one")).unwrap();
        assert_eq!(first.parent, owner.parent);
        assert_eq!(error(owner.reserve(&request("one"))), LeaseError::Replay);
        assert_eq!(error(owner.reserve(&request("two"))), LeaseError::Busy);
        assert_eq!(
            owner.confirm_child_destroyed(&Hash::of(b"impostor")),
            Err(LeaseError::Owner)
        );
        owner.confirm_child_destroyed(&first.child).unwrap();
        assert_eq!(error(owner.reserve(&request("one"))), LeaseError::Replay);
        let second = owner.reserve(&request("two")).unwrap();
        assert_ne!(first.child, second.child);
        owner.confirm_child_destroyed(&second.child).unwrap();
        assert_eq!(error(owner.reserve(&request("three"))), LeaseError::Budget);
    }

    #[test]
    fn stop_retains_cleanup_owner_and_does_not_refund() {
        let mut owner = lease();
        let turn = owner.reserve(&request("one")).unwrap();
        assert_eq!(owner.stop(), Some(turn.child.clone()));
        assert_eq!(owner.stop(), Some(turn.child.clone()));
        assert_eq!(error(owner.reserve(&request("two"))), LeaseError::Stopped);
        owner.confirm_child_destroyed(&turn.child).unwrap();
        assert_eq!(owner.stop(), None);
        assert_eq!(error(owner.reserve(&request("three"))), LeaseError::Stopped);
        assert_eq!(owner.requests_left, 3);
    }

    #[test]
    fn expiry_caps_child_time_and_permanently_closes_admission() {
        let mut owner = lease();
        let near_end = owner.deadline - Duration::from_millis(7);
        let turn = owner.reserve_at(&request("one"), near_end).unwrap();
        assert_eq!(turn.limits.timeout, Duration::from_millis(7));
        owner.confirm_child_destroyed(&turn.child).unwrap();
        assert_eq!(
            error(owner.reserve_at(&request("two"), owner.deadline)),
            LeaseError::Stopped
        );
        assert_eq!(
            error(owner.reserve_at(&request("two"), near_end)),
            LeaseError::Stopped
        );
    }

    #[test]
    fn invalid_guest_input_spends_nothing_and_new_parent_has_distinct_identity() {
        let mut owner = lease();
        assert_eq!(error(owner.reserve(b"{}")), LeaseError::Protocol);
        assert_eq!(owner.turns_left, 4);
        let mut other = lease();
        other.parent = Hash::of(b"different-incarnation");
        assert_ne!(
            owner.reserve(&request("one")).unwrap().child,
            other.reserve(&request("one")).unwrap().child
        );
    }

    #[test]
    fn model_free_work_still_has_bounded_turn_count() {
        let mut owner = ParentLease::new(
            Hash::of(b"direct-worker"),
            Duration::from_secs(1),
            TurnLimits {
                memory_bytes: 4096,
                timeout: Duration::from_millis(10),
                model_requests: 0,
                output_tokens: 0,
            },
            1,
            0,
            0,
        )
        .unwrap();
        let turn = owner.reserve(&request("one")).unwrap();
        owner.confirm_child_destroyed(&turn.child).unwrap();
        assert_eq!(error(owner.reserve(&request("two"))), LeaseError::Budget);
        assert_eq!(
            owner.confirm_child_destroyed(&turn.child),
            Err(LeaseError::Owner)
        );
    }
}
