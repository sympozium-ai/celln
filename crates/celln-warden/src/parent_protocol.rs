//! Bounded data protocol for a future persistent Harness parent's turn worker.
//!
//! This is a parser, NOT spawn authority or an implemented persistent VM path.
//! The host must bind every accepted request to an admitted parent, lease,
//! monotonic turn record, worker and narrowed grants before creating a child.
//! No executable hashes, credentials, endpoints or resource grants come from
//! this untrusted guest request. Existing invocation/HTTPS PIO ABIs are unchanged.

use serde::{Deserialize, Serialize};

pub const VERSION: &str = "celln.parent-turn/v1";
pub const MAX_REQUEST_BYTES: usize = 8192;
pub const MAX_TASK_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TurnRequest {
    pub api_version: String,
    /// Idempotency data, scoped by the host to this parent identity. This is
    /// never sufficient to select another parent's execution owner.
    pub turn_id: String,
    /// Input to the admitted native turn worker, not a host command.
    pub task: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("parent turn request exceeds its encoded bound or is empty")]
    Size,
    #[error("invalid parent turn JSON envelope")]
    Envelope,
    #[error("unsupported parent turn protocol version")]
    Version,
    #[error("invalid parent-scoped turn identity")]
    Identity,
    #[error("turn task is empty, contains NUL, or exceeds worker input bound")]
    Task,
}

impl TurnRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
            return Err(ProtocolError::Size);
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| ProtocolError::Envelope)?;
        if request.api_version != VERSION {
            return Err(ProtocolError::Version);
        }
        if request.turn_id.is_empty()
            || request.turn_id.len() > 64
            || !request
                .turn_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ProtocolError::Identity);
        }
        if request.task.trim().is_empty()
            || request.task.len() > MAX_TASK_BYTES
            || request.task.contains('\0')
        {
            return Err(ProtocolError::Task);
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(task: &str) -> serde_json::Value {
        serde_json::json!({"apiVersion": VERSION, "turnId": "turn-1", "task": task})
    }

    #[test]
    fn accepts_bounded_task_data_without_authority_fields() {
        let value = envelope("Use the approved worker to answer the next message.");
        let request = TurnRequest::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(request.turn_id, "turn-1");
    }

    #[test]
    fn refuses_guest_supplied_authority_and_duplicate_or_trailing_fields() {
        for name in [
            "parentId",
            "childId",
            "executable",
            "toolRefs",
            "token",
            "endpoint",
            "memoryBytes",
            "lease",
        ] {
            let mut value = envelope("hello");
            value[name] = serde_json::json!("untrusted");
            assert_eq!(
                TurnRequest::decode(&serde_json::to_vec(&value).unwrap()),
                Err(ProtocolError::Envelope)
            );
        }
        assert_eq!(TurnRequest::decode(br#"{"apiVersion":"celln.parent-turn/v1","turnId":"a","turnId":"b","task":"hello"}"#), Err(ProtocolError::Envelope));
        let mut bytes = serde_json::to_vec(&envelope("hello")).unwrap();
        bytes.extend(b"{}");
        assert_eq!(TurnRequest::decode(&bytes), Err(ProtocolError::Envelope));
    }

    #[test]
    fn refuses_unknown_versions_and_unsafe_identities() {
        let mut value = envelope("hello");
        value["apiVersion"] = serde_json::json!("celln.parent-turn/v2");
        assert_eq!(
            TurnRequest::decode(&serde_json::to_vec(&value).unwrap()),
            Err(ProtocolError::Version)
        );
        for id in ["", "../other-parent", "other/turn", "with space"] {
            let mut value = envelope("hello");
            value["turnId"] = serde_json::json!(id);
            assert_eq!(
                TurnRequest::decode(&serde_json::to_vec(&value).unwrap()),
                Err(ProtocolError::Identity)
            );
        }
    }

    #[test]
    fn enforces_encoded_and_utf8_byte_bounds() {
        assert_eq!(TurnRequest::decode(&[]), Err(ProtocolError::Size));
        assert_eq!(
            TurnRequest::decode(&vec![b' '; MAX_REQUEST_BYTES + 1]),
            Err(ProtocolError::Size)
        );
        for task in [
            String::new(),
            "\0".into(),
            "x".repeat(MAX_TASK_BYTES + 1),
            "é".repeat(1025),
        ] {
            assert_eq!(
                TurnRequest::decode(&serde_json::to_vec(&envelope(&task)).unwrap()),
                Err(ProtocolError::Task)
            );
        }
        TurnRequest::decode(&serde_json::to_vec(&envelope(&"x".repeat(MAX_TASK_BYTES))).unwrap())
            .unwrap();
    }
}
