//! Native enduring Harness context owner. Model/tool work belongs to a separate
//! admitted turn worker. This module never chooses executable or model authority.
use crate::json_harness::Exchange;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use warden::parent_mailbox::MAX_FRAME_BYTES;
use warden::parent_protocol::{TurnRequest, MAX_ANSWER_BYTES, MAX_MESSAGE_BYTES, MAX_TASK_BYTES};

pub const VERSION: &str = "celln.parent-context/v1";

/// Most prior exchanges a continued conversation may seed a new parent with,
/// and the room a seed must leave inside the turn bound for the first
/// message that follows it.
pub const MAX_SEED_EXCHANGES: usize = 16;
pub const SEED_HEADROOM_BYTES: usize = 512;

/// Most exchanges a worker task carries, and so the most a parent retains:
/// the worker contract refuses a longer history.
pub const MAX_TASK_EXCHANGES: usize = MAX_SEED_EXCHANGES;
/// Appended to an answer cut short so the newest exchange fits a task.
pub const TRUNCATION_MARKER: &str = "…[truncated]";

fn encode_task(history: &[Exchange], message: &str) -> Result<String, &'static str> {
    serde_json::to_string(&serde_json::json!({"history":history, "message":message}))
        .map_err(|_| "context encoding failed")
}

/// Pack the worker task `{"history":[…],"message":…}` inside `bound` bytes.
/// The new message is always kept whole. The newest exchanges are kept, as
/// many as fit (at most `MAX_TASK_EXCHANGES`), and older ones are left out.
/// When not even the newest exchange fits beside the message, its answer is
/// cut at a character boundary and marked, or left out if nothing useful
/// would remain. Only a message that cannot fit alone is an error.
pub fn pack_task(
    history: &[Exchange],
    message: &str,
    bound: usize,
) -> Result<String, &'static str> {
    let empty = encode_task(&[], message)?;
    if empty.len() > bound {
        return Err("message exceeds the worker task bound");
    }
    let mut room = bound - empty.len();
    let mut start = history.len();
    while start > 0 && history.len() - start < MAX_TASK_EXCHANGES {
        let encoded = serde_json::to_string(&history[start - 1])
            .map_err(|_| "context encoding failed")?
            .len();
        // Every exchange after the first also costs its separating comma.
        let cost = encoded + usize::from(start < history.len());
        if cost > room {
            break;
        }
        room -= cost;
        start -= 1;
    }
    if start < history.len() || history.is_empty() {
        return encode_task(&history[start..], message);
    }
    let newest = &history[history.len() - 1];
    let fits = |end: usize| -> bool {
        let cut = Exchange {
            user: newest.user.clone(),
            assistant: format!("{}{TRUNCATION_MARKER}", &newest.assistant[..end]),
        };
        serde_json::to_string(&cut).is_ok_and(|encoded| encoded.len() <= room)
    };
    // Encoded length grows with the kept prefix: search its boundaries.
    let boundaries: Vec<usize> = newest
        .assistant
        .char_indices()
        .map(|(index, _)| index)
        .collect();
    // boundaries[0] is 0: an answer with nothing kept is left out instead.
    let (mut low, mut high) = (0usize, boundaries.len().saturating_sub(1));
    while low < high {
        let middle = (low + high).div_ceil(2);
        if fits(boundaries[middle]) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    let end = boundaries.get(low).copied().unwrap_or(0);
    if end == 0 {
        return Ok(empty);
    }
    encode_task(
        &[Exchange {
            user: newest.user.clone(),
            assistant: format!("{}{TRUNCATION_MARKER}", &newest.assistant[..end]),
        }],
        message,
    )
}

/// Check a seed before any host state depends on it: bounded count, text
/// only, and small enough that a first message still fits the turn bound.
pub fn validate_seed(history: &[Exchange]) -> Result<(), &'static str> {
    if history.len() > MAX_SEED_EXCHANGES {
        return Err("seed exceeds exchange count");
    }
    if history.iter().any(|exchange| {
        // The worker contract refuses an empty side of an exchange.
        exchange.user.trim().is_empty()
            || exchange.assistant.trim().is_empty()
            || exchange.user.contains('\0')
            || exchange.assistant.contains('\0')
    }) {
        return Err("seed exchanges must be non-empty text");
    }
    let encoded = serde_json::to_vec(&serde_json::json!({"history":history, "message":""}))
        .map_err(|_| "seed encoding failed")?;
    if encoded.len() + SEED_HEADROOM_BYTES > MAX_TASK_BYTES {
        return Err("seed leaves no room for a first message");
    }
    Ok(())
}

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
    /// Prior exchanges of a conversation this parent continues, delivered by
    /// the host once, before any turn. A seeded parent starts with memory;
    /// nothing in a seed is a turn, a result or an instruction.
    Seed {
        #[serde(rename = "apiVersion")]
        api_version: String,
        history: Vec<Exchange>,
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
    Seeded {
        #[serde(rename = "apiVersion")]
        api_version: String,
        exchanges: usize,
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
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err("message bound exceeded");
        }
        let message: HostMessage =
            serde_json::from_slice(bytes).map_err(|_| "invalid parent message")?;
        match message {
            HostMessage::Seed {
                api_version,
                history,
            } => {
                if api_version != VERSION {
                    return Err("unsupported parent version");
                }
                // Only an untouched context accepts memory: never after a
                // turn was seen, never while one is pending, never twice.
                if !self.history.is_empty() || self.pending.is_some() || !self.seen.is_empty() {
                    return Err("seed refused: context already in use");
                }
                validate_seed(&history)?;
                let exchanges = history.len();
                self.history = history;
                Ok(ParentReply::Seeded {
                    api_version: VERSION.into(),
                    exchanges,
                })
            }
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
                // A message this parent cannot carry fails that turn only.
                // The context is untouched and the turn identity unused, so
                // the conversation continues with the next message.
                let refused = |reason: &str| {
                    Ok(ParentReply::Completed {
                        api_version: VERSION.into(),
                        turn_id: turn_id.clone(),
                        succeeded: false,
                        answer: format!("Turn refused; no worker started: {reason}"),
                    })
                };
                if message.trim().is_empty() || message.contains('\0') {
                    return refused("the message is empty or contains NUL");
                }
                if message.len() > MAX_MESSAGE_BYTES {
                    return refused("the message exceeds 2048 bytes");
                }
                // Explicit structured context. A conversation longer than the
                // worker task bound keeps its newest exchanges; the oldest
                // are left out of this task rather than ending the parent.
                let Ok(task) = pack_task(&self.history, &message, MAX_TASK_BYTES) else {
                    return refused("the message does not fit a worker task");
                };
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
                if answer.len() > MAX_ANSWER_BYTES
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
                    // No task carries more; older exchanges are never read.
                    let excess = self.history.len().saturating_sub(MAX_TASK_EXCHANGES);
                    self.history.drain(..excess);
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
    fn seed_gives_a_new_parent_memory_once_and_only_before_its_first_turn() {
        let mut context = ParentContext::default();
        let seed = serde_json::json!({"kind":"seed","apiVersion":VERSION,"history":[
            {"user":"remember the word saffron","assistant":"Noted: saffron."},
            {"user":"and the number seven","assistant":"Seven, noted."}
        ]});
        let reply = context.exchange(seed.to_string().as_bytes()).unwrap();
        assert!(matches!(reply, ParentReply::Seeded { exchanges: 2, .. }));
        // The first turn carries the seeded exchanges as its history.
        let turn = serde_json::json!({"kind":"turn","apiVersion":VERSION,"turnId":"one","message":"which word?"});
        let ParentReply::Spawn { request } = context.exchange(turn.to_string().as_bytes()).unwrap()
        else {
            panic!("turn must spawn a worker");
        };
        let task: serde_json::Value = serde_json::from_str(&request.task).unwrap();
        assert_eq!(task["history"][0]["user"], "remember the word saffron");
        assert_eq!(task["history"][1]["assistant"], "Seven, noted.");
        assert_eq!(task["message"], "which word?");
        // Never twice, never with a turn pending, never after a turn was seen.
        assert!(context.exchange(seed.to_string().as_bytes()).is_err());
        let mut used = ParentContext::default();
        used.exchange(turn.to_string().as_bytes()).unwrap();
        assert!(used.exchange(seed.to_string().as_bytes()).is_err());
        // Bounds: count, text, and room for a first message.
        let many: Vec<_> = (0..MAX_SEED_EXCHANGES + 1)
            .map(|i| Exchange {
                user: format!("u{i}"),
                assistant: "a".into(),
            })
            .collect();
        assert_eq!(validate_seed(&many), Err("seed exceeds exchange count"));
        assert!(validate_seed(&[Exchange {
            user: " ".into(),
            assistant: "a".into()
        }])
        .is_err());
        assert!(validate_seed(&[Exchange {
            user: "u".into(),
            assistant: "a\0".into()
        }])
        .is_err());
        assert!(validate_seed(&[Exchange {
            user: "u".into(),
            assistant: " ".into()
        }])
        .is_err());
        // What filled the first 2 KiB contract is now an ordinary seed.
        assert!(validate_seed(&[Exchange {
            user: "u".repeat(900),
            assistant: "a".repeat(900),
        }])
        .is_ok());
        let wide = vec![Exchange {
            user: "u".repeat(MAX_TASK_BYTES / 2),
            assistant: "a".repeat(MAX_TASK_BYTES / 2),
        }];
        assert_eq!(
            validate_seed(&wide),
            Err("seed leaves no room for a first message")
        );
        assert!(validate_seed(&[]).is_ok());
        let mut fresh = ParentContext::default();
        assert!(matches!(
            fresh.exchange(
                serde_json::json!({"kind":"seed","apiVersion":"other","history":[]})
                    .to_string()
                    .as_bytes()
            ),
            Err("unsupported parent version")
        ));
    }

    #[test]
    fn oversize_message_and_unknown_authority_fail_without_consuming_turn() {
        let mut parent = ParentContext::default();
        parent
            .exchange(&turn("zero", "my value is violet"))
            .unwrap();
        parent.exchange(&result("zero", true)).unwrap();
        // The turn fails with a readable result; the parent keeps running
        // with its context, and the turn identity stays unused.
        for message in ["x".repeat(MAX_MESSAGE_BYTES + 1), "nul\0".into()] {
            let ParentReply::Completed {
                turn_id,
                succeeded,
                answer,
                ..
            } = parent.exchange(&turn("one", &message)).unwrap()
            else {
                panic!("an unusable message must fail its turn, not the parent")
            };
            assert_eq!(turn_id, "one");
            assert!(!succeeded && answer.starts_with("Turn refused; no worker started"));
        }
        assert!(parent.pending.is_none() && !parent.seen.contains("one"));
        assert_eq!(parent.history.len(), 1);
        let mut forged: serde_json::Value = serde_json::from_slice(&turn("one", "hello")).unwrap();
        forged["executable"] = serde_json::json!("unapproved");
        assert!(parent
            .exchange(&serde_json::to_vec(&forged).unwrap())
            .is_err());
        let ParentReply::Spawn { request } = parent
            .exchange(&turn("one", &"x".repeat(MAX_MESSAGE_BYTES)))
            .unwrap()
        else {
            panic!()
        };
        assert!(request.task.contains("my value is violet"));
    }

    fn exchange(user: &str, assistant: &str) -> Exchange {
        Exchange {
            user: user.into(),
            assistant: assistant.into(),
        }
    }
    fn unpack(task: &str) -> (Vec<Exchange>, String) {
        let context = crate::turn_worker::ContextInput::decode(task).unwrap();
        (context.history, context.message)
    }

    #[test]
    fn a_history_that_fits_is_packed_untouched() {
        let history = vec![exchange("one", "first"), exchange("two", "second")];
        let task = pack_task(&history, "three", MAX_TASK_BYTES).unwrap();
        assert_eq!(
            task,
            serde_json::json!({"history":history, "message":"three"}).to_string()
        );
        // Exactly at the bound is still untouched; one byte less is not.
        let exact = pack_task(&history, "three", task.len()).unwrap();
        assert_eq!(exact, task);
        let (kept, _) = unpack(&pack_task(&history, "three", task.len() - 1).unwrap());
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].user, "two");
    }

    #[test]
    fn the_oldest_exchanges_are_trimmed_first_and_the_newest_kept() {
        let history: Vec<_> = (0..12)
            .map(|i| exchange(&format!("question {i}"), &"a".repeat(1800)))
            .collect();
        let task = pack_task(&history, "and now?", MAX_TASK_BYTES).unwrap();
        assert!(task.len() <= MAX_TASK_BYTES);
        let (kept, message) = unpack(&task);
        assert_eq!(message, "and now?");
        assert!(kept.len() < history.len() && kept.len() >= 8);
        // A contiguous run ending at the newest exchange, in order.
        for (kept, original) in kept.iter().zip(&history[history.len() - kept.len()..]) {
            assert_eq!(kept.user, original.user);
            assert_eq!(kept.assistant, original.assistant);
        }
        assert_eq!(kept.last().unwrap().user, "question 11");
        // The next older exchange really would not have fitted.
        let wider = &history[history.len() - kept.len() - 1..];
        assert!(encode_task(wider, "and now?").unwrap().len() > MAX_TASK_BYTES);
        // Never more exchanges than the worker contract reads.
        let many: Vec<_> = (0..40).map(|i| exchange(&format!("q{i}"), "a")).collect();
        let (kept, _) = unpack(&pack_task(&many, "next", MAX_TASK_BYTES).unwrap());
        assert_eq!(kept.len(), MAX_TASK_EXCHANGES);
        assert_eq!(kept[0].user, "q24");
    }

    #[test]
    fn a_lone_exchange_too_wide_is_cut_at_a_character_boundary_and_marked() {
        // Two-byte characters and an odd amount of room force a cut that a
        // byte index would place inside a character.
        let history = vec![
            exchange("old", "gone"),
            exchange("recent", &"é".repeat(600)),
        ];
        for bound in [400, 401, 402, 403] {
            let task = pack_task(&history, "continue", bound).unwrap();
            assert!(task.len() <= bound);
            let (kept, message) = unpack(&task);
            assert_eq!(message, "continue");
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].user, "recent");
            let text = kept[0].assistant.strip_suffix(TRUNCATION_MARKER).unwrap();
            assert!(!text.is_empty() && text.chars().all(|c| c == 'é'));
            // As much as fits: one more character would overflow.
            let longer = exchange("recent", &format!("{text}é{TRUNCATION_MARKER}"));
            assert!(encode_task(&[longer], "continue").unwrap().len() > bound);
        }
        // Escaped text is measured as encoded, not as raw bytes.
        let quoted = vec![exchange("recent", &"\"".repeat(600))];
        let task = pack_task(&quoted, "continue", 400).unwrap();
        assert!(task.len() <= 400);
        assert!(unpack(&task).0[0].assistant.ends_with(TRUNCATION_MARKER));
        // No room for anything useful: the exchange is left out, not faked.
        let (kept, _) = unpack(&pack_task(&history, "continue", 60).unwrap());
        assert!(kept.is_empty());
    }

    #[test]
    fn only_a_message_that_cannot_fit_alone_fails_and_nothing_panics() {
        let history = vec![exchange("recent", "answer")];
        let alone = encode_task(&[], "message").unwrap().len();
        assert!(pack_task(&history, "message", alone).is_ok());
        for bound in [0, 1, alone - 1] {
            assert_eq!(
                pack_task(&history, "message", bound),
                Err("message exceeds the worker task bound")
            );
        }
        // The widest legal message (every byte escaped sixfold) fits alone.
        assert!(pack_task(&[], &"\u{1}".repeat(MAX_MESSAGE_BYTES), MAX_TASK_BYTES).is_ok());
    }

    #[test]
    fn a_long_conversation_never_stops_the_parent_and_seeds_are_trimmed_too() {
        let mut parent = ParentContext::default();
        let seed: Vec<_> = (0..MAX_SEED_EXCHANGES)
            .map(|i| exchange(&format!("seeded {i}"), &"s".repeat(900)))
            .collect();
        parent
            .exchange(
                serde_json::json!({"kind":"seed","apiVersion":VERSION,"history":seed})
                    .to_string()
                    .as_bytes(),
            )
            .unwrap();
        for index in 0..40 {
            let id = format!("turn-{index}");
            let ParentReply::Spawn { request } = parent
                .exchange(&turn(&id, &format!("message {index} {}", "m".repeat(1500))))
                .unwrap()
            else {
                panic!("turn {index} must reach a worker")
            };
            assert!(request.task.len() <= MAX_TASK_BYTES);
            let (kept, message) = unpack(&request.task);
            assert!(message.starts_with(&format!("message {index} ")));
            if index > 0 {
                assert!(kept
                    .last()
                    .unwrap()
                    .user
                    .starts_with(&format!("message {} ", index - 1)));
            }
            let answer = "w".repeat(MAX_ANSWER_BYTES);
            parent.exchange(&serde_json::to_vec(&serde_json::json!({"kind":"result", "apiVersion":VERSION, "turnId":id, "succeeded":true, "answer":answer})).unwrap()).unwrap();
            assert!(parent.history.len() <= MAX_TASK_EXCHANGES);
        }
    }

    #[test]
    fn answers_are_bounded_at_the_answer_contract() {
        let answered = |bytes: usize| {
            let mut parent = ParentContext::default();
            parent.exchange(&turn("one", "hello")).unwrap();
            parent.exchange(&serde_json::to_vec(&serde_json::json!({"kind":"result", "apiVersion":VERSION, "turnId":"one", "succeeded":true, "answer":"a".repeat(bytes)})).unwrap())
        };
        assert_eq!(MAX_ANSWER_BYTES, 8192);
        assert!(answered(MAX_ANSWER_BYTES).is_ok());
        assert_eq!(
            answered(MAX_ANSWER_BYTES + 1).unwrap_err(),
            "invalid worker answer"
        );
        // Every frame such a turn produces fits the mailbox, even when the
        // whole answer needs sixfold escaping.
        let mut parent = ParentContext::default();
        parent.exchange(&turn("one", "hello")).unwrap();
        let frame = serde_json::to_vec(&serde_json::json!({"kind":"result", "apiVersion":VERSION, "turnId":"one", "succeeded":true, "answer":"\u{1}".repeat(MAX_ANSWER_BYTES)})).unwrap();
        assert!(frame.len() <= MAX_FRAME_BYTES);
        let reply = serde_json::to_vec(&parent.exchange(&frame).unwrap()).unwrap();
        assert!(reply.len() <= MAX_FRAME_BYTES);
        let spawn = parent
            .exchange(&turn("two", &"\"".repeat(MAX_MESSAGE_BYTES)))
            .unwrap();
        assert!(serde_json::to_vec(&spawn).unwrap().len() <= MAX_FRAME_BYTES);
    }
}
