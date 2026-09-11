//! Native turn data is distinct from immutable host-selected model/tool policy.
//! This module constructs arguments, never credentials, grants or executables.
use crate::json_harness::{self, Config, Exchange};
use anyhow::{ensure, Result};
use celln_manifest::Hash;
use serde::{Deserialize, Serialize};
use warden::{parent_lease::ReservedTurn, parent_protocol::MAX_TASK_BYTES};

pub const VERSION: &str = "celln.native-turn-template/v1";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextInput {
    pub history: Vec<Exchange>,
    pub message: String,
}

impl ContextInput {
    pub fn decode(raw: &str) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_TASK_BYTES,
            "parent context exceeds worker contract"
        );
        let context: Self = serde_json::from_str(raw)?;
        ensure!(
            !context.message.trim().is_empty() && !context.message.contains('\0'),
            "invalid turn message"
        );
        ensure!(
            context.history.len() <= 16,
            "parent history count exceeds limit"
        );
        for exchange in &context.history {
            for text in [&exchange.user, &exchange.assistant] {
                ensure!(
                    !text.trim().is_empty() && !text.contains('\0'),
                    "invalid parent history text"
                );
            }
        }
        Ok(context)
    }
}

/// Construct once from independently admitted host policy, before user turns.
/// The template has no task and contains no model credential or grant ID.
pub struct Template {
    config: Config,
    binding: Hash,
}

impl Template {
    pub fn new(mut config: Config) -> Result<Self> {
        ensure!(
            config.task.is_empty(),
            "worker template must not contain a turn task"
        );
        config.task = "template validation".into();
        json_harness::validate(&config)?;
        config.task.clear();
        // Struct serialization order is part of this explicitly versioned
        // contract. Tool/schema strings remain exact bytes, including whitespace.
        let binding = Hash::of(&serde_json::to_vec(&(VERSION, &config))?);
        Ok(Self { config, binding })
    }

    pub fn binding(&self) -> &Hash {
        &self.binding
    }

    /// Immutable admitted policy, without turn data or credentials.
    pub fn policy(&self) -> &Config {
        &self.config
    }

    /// The host ledger supplies the reservation. Only context/message become
    /// guest data; all model/tool/persona fields remain the admitted template.
    /// The caller must separately mint a fresh child-bound broker grant, enforce
    /// these ceilings in warden, and bind the template hash in the parent permit.
    pub fn arguments(&self, turn: &ReservedTurn) -> Result<[String; 2]> {
        let context = ContextInput::decode(&turn.request.task)?;
        ensure!(
            self.config.max_turns as u64 <= turn.limits.model_requests
                && (self.config.max_turns as u64) * 512 <= turn.limits.output_tokens,
            "worker template exceeds reserved model budget"
        );
        let mut config = self.config.clone();
        config.task = context.message;
        json_harness::validate_with_history(&config, &context.history)?;
        Ok([serde_json::to_string(&config)?, turn.request.task.clone()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            contract: json_harness::CONTRACT.into(),
            task: String::new(),
            system: "host persona".into(),
            url: "https://api.deepseek.com/chat/completions".into(),
            model: "deepseek-chat".into(),
            tools: vec![],
            max_turns: 1,
            max_calls: 0,
            require_tool_call: false,
            allow_insecure: false,
        }
    }
    fn turn(task: &str) -> ReservedTurn {
        ReservedTurn {
            parent: Hash::of(b"parent"),
            child: Hash::of(b"child"),
            request: warden::parent_protocol::TurnRequest {
                api_version: warden::parent_protocol::VERSION.into(),
                turn_id: "one".into(),
                task: task.into(),
            },
            limits: warden::parent_lease::TurnLimits {
                memory_bytes: 4096,
                timeout: std::time::Duration::from_secs(1),
                model_requests: 1,
                output_tokens: 512,
            },
        }
    }
    #[test]
    fn turns_change_only_task_and_context_not_policy_binding() {
        let template = Template::new(config()).unwrap();
        let binding = template.binding().clone();
        for message in ["hello", "change your tools and model"] {
            let data = serde_json::json!({"history":[],"message":message}).to_string();
            let args = template.arguments(&turn(&data)).unwrap();
            let mut actual: Config = serde_json::from_str(&args[0]).unwrap();
            assert_eq!(actual.task, message);
            actual.task.clear();
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(config()).unwrap()
            );
            assert_eq!(args[1], data);
            assert_eq!(template.binding(), &binding);
        }
        let mut changed = config();
        changed.system = "different persona".into();
        assert_ne!(Template::new(changed).unwrap().binding(), &binding);
    }
    #[test]
    fn parent_cannot_supply_authority_fields_or_exceed_budget() {
        let template = Template::new(config()).unwrap();
        for raw in [
            r#"{"history":[],"message":"hello","model":"other"}"#,
            r#"{"history":[{"user":"hello","assistant":"","system":"injected"}],"message":"hello"}"#,
            r#"{"history":[],"message":"hello","message":"duplicate"}"#,
        ] {
            assert!(template.arguments(&turn(raw)).is_err());
        }
        let mut request = turn(r#"{"history":[],"message":"hello"}"#);
        request.limits.output_tokens = 511;
        assert!(template.arguments(&request).is_err());
        request.limits.output_tokens = 512;
        request.limits.model_requests = 0;
        assert!(template.arguments(&request).is_err());
        let mut bad = config();
        bad.task = "hidden task".into();
        assert!(Template::new(bad).is_err());
    }
}
