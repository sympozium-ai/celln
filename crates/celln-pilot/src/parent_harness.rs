//! Native enduring Harness context owner. Model/tool work belongs to a separate
//! admitted turn worker. This module never chooses executable or model authority.
use crate::json_harness::Exchange;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use warden::parent_protocol::{TurnRequest, MAX_REQUEST_BYTES, MAX_TASK_BYTES};

pub const VERSION: &str = "celln.parent-context/v1";

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum HostMessage {
    Turn {
        #[serde(rename = "apiVersion")]
        api_version: String,
        #[serde(rename = "turnId")]
        turn_id: String,
        message: String,
    },
    Result {
        #[serde(rename = "apiVersion")]
        api_version: String,
        #[serde(rename = "turnId")]
        turn_id: String,
        succeeded: bool,
        answer: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ParentReply {
    Spawn {
        request: TurnRequest,
    },
    Completed {
        #[serde(rename = "apiVersion")]
        api_version: String,
        #[serde(rename = "turnId")]
        turn_id: String,
        succeeded: bool,
        answer: String,
    },
}

#[derive(Default)]
pub struct ParentContext {
    history: Vec<Exchange>,
    pending: Option<(String, String)>,
    seen: BTreeSet<String>,
}

impl ParentContext {
    /// Reject before mutating state. Invalid or mismatched results are not
    /// interpreted as successful turns; failed work does not enter context.
    pub fn exchange(&mut self, bytes: &[u8]) -> Result<ParentReply, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
            return Err("message bound exceeded");
        }
        let message: HostMessage =
            serde_json::from_slice(bytes).map_err(|_| "invalid parent message")?;
        match message {
            HostMessage::Turn {
                api_version,
                turn_id,
                message,
            } => {
                if api_version != VERSION {
                    return Err("unsupported parent version");
                }
                if self.pending.is_some() {
                    return Err("turn still pending");
                }
                if self.seen.contains(&turn_id) || self.seen.len() >= 1024 {
                    return Err("turn replay or count exhausted");
                }
                if message.trim().is_empty() || message.contains('\0') {
                    return Err("invalid user message");
                }
                // Explicit structured context, not a silently truncated prompt.
                // The existing worker's 2 KiB bound still applies until the
                // coordinated worker/spec/runtime contract is extended.
                let task = serde_json::to_string(&serde_json::json!({
                    "history":self.history, "message":message
                }))
                .map_err(|_| "context encoding failed")?;
                let request = TurnRequest {
                    api_version: warden::parent_protocol::VERSION.into(),
                    turn_id: turn_id.clone(),
                    task,
                };
                let encoded =
                    serde_json::to_vec(&request).map_err(|_| "request encoding failed")?;
                TurnRequest::decode(&encoded)
                    .map_err(|_| "invalid turn identity or worker context full")?;
                self.seen.insert(turn_id.clone());
                self.pending = Some((turn_id, message));
                Ok(ParentReply::Spawn { request })
            }
            HostMessage::Result {
                api_version,
                turn_id,
                succeeded,
                answer,
            } => {
                if api_version != VERSION {
                    return Err("unsupported parent version");
                }
                let (id, _) = self.pending.as_ref().ok_or("no pending turn")?;
                if id != &turn_id {
                    return Err("result identity mismatch");
                }
                if answer.len() > MAX_TASK_BYTES
                    || answer.contains('\0')
                    || (succeeded && answer.trim().is_empty())
                {
                    return Err("invalid worker answer");
                }
                let (_, user) = self.pending.take().unwrap();
                if succeeded {
                    self.history.push(Exchange {
                        user,
                        assistant: answer.clone(),
                    });
                }
                Ok(ParentReply::Completed {
                    api_version: VERSION.into(),
                    turn_id,
                    succeeded,
                    answer,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn turn(id: &str, message: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"kind":"turn", "apiVersion":VERSION, "turnId":id, "message":message})).unwrap()
    }
    fn result(id: &str, succeeded: bool) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"kind":"result", "apiVersion":VERSION, "turnId":id, "succeeded":succeeded, "answer":"remembered"})).unwrap()
    }
    #[test]
    fn next_worker_receives_committed_guest_context() {
        let mut parent = ParentContext::default();
        parent.exchange(&turn("one", "my value is violet")).unwrap();
        parent.exchange(&result("one", true)).unwrap();
        let ParentReply::Spawn { request } = parent.exchange(&turn("two", "what was it?")).unwrap()
        else {
            panic!()
        };
        let task: serde_json::Value = serde_json::from_str(&request.task).unwrap();
        assert_eq!(task["history"][0]["user"], "my value is violet");
        assert_eq!(task["history"][0]["assistant"], "remembered");
        assert_eq!(task["message"], "what was it?");
    }
    #[test]
    fn mismatched_results_busy_turns_and_replays_do_not_change_context() {
        let mut parent = ParentContext::default();
        parent.exchange(&turn("one", "secret")).unwrap();
        assert!(parent.exchange(&turn("two", "busy")).is_err());
        assert!(parent.exchange(&result("other", true)).is_err());
        assert!(parent.history.is_empty());
        parent.exchange(&result("one", false)).unwrap();
        assert!(parent.history.is_empty());
        assert!(parent.exchange(&turn("one", "replay")).is_err());
        parent.exchange(&turn("two", "next")).unwrap();
    }
    #[test]
    fn context_overflow_and_unknown_authority_fail_without_consuming_turn() {
        let mut parent = ParentContext::default();
        assert!(parent
            .exchange(&turn("one", &"x".repeat(MAX_TASK_BYTES)))
            .is_err());
        assert!(parent.seen.is_empty());
        let mut forged: serde_json::Value = serde_json::from_slice(&turn("one", "hello")).unwrap();
        forged["executable"] = serde_json::json!("unapproved");
        assert!(parent
            .exchange(&serde_json::to_vec(&forged).unwrap())
            .is_err());
        parent.exchange(&turn("one", "hello")).unwrap();
    }
}
