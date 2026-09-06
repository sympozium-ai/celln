//! Additive audit envelope: the strict v1alpha1 receipt stays byte/schema
//! compatible. No arguments, environment, input bytes or diagnostics here.

use crate::dispatch::{BrokerActivity, LaunchOutcome, SubstrateIdentity};
use celln_spec::{CapabilityRequest, ExecutionReceipt, ExecutionRequest};
use serde::Serialize;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Audit {
    pub api_version: &'static str,
    pub request_id: String,
    pub caller: String,
    pub workload: String,
    pub node: String,
    pub events: Vec<Event>,
    pub execution: Option<Execution>,
    pub receipt: Option<ExecutionReceipt>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub sequence: usize,
    pub at: String,
    pub phase: String,
    #[serde(skip)]
    observed: std::time::Instant,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Execution {
    pub cell_id: String,
    pub substrate: Option<SubstrateIdentity>,
    pub pilot: Option<pilot::dispatch_report::ExecutionGrant>,
    /// Only populated after pilot's installed-grant acknowledgement matches
    /// host-enforced bounds. A refused setup does not grant requested authority.
    pub granted: Option<CapabilityRequest>,
    pub inputs: Vec<String>,
    pub broker: BrokerActivity,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub watchdog_stopped: bool,
}

impl Audit {
    pub fn new(request: &ExecutionRequest, node: &str) -> Self {
        let mut audit = Self {
            api_version: "celln.dev/audit-v1alpha1",
            request_id: request.id.clone(),
            caller: request.workload.caller.clone(),
            workload: request.workload.id.clone(),
            node: node.into(),
            events: Vec::new(),
            execution: None,
            receipt: None,
        };
        audit.phase("Admitting");
        audit
    }

    pub fn phase(&mut self, phase: &str) {
        if self.events.last().is_some_and(|event| event.phase == phase) {
            return;
        }
        // Lifecycle has a fixed small number of phases; repeated cancellation
        // polls must not become an unbounded audit-log allocator.
        if self.events.len() < 32 {
            self.events.push(Event {
                sequence: self.events.len(),
                at: crate::dispatch::now_rfc3339(),
                phase: phase.into(),
                observed: std::time::Instant::now(),
            });
        }
    }

    pub fn executed(&mut self, request: &ExecutionRequest, outcome: &LaunchOutcome) {
        for event in &outcome.lifecycle {
            if self.events.len() < 32 {
                self.events.push(Event {
                    sequence: self.events.len(),
                    at: event.at.clone(),
                    phase: event.phase.clone(),
                    observed: event.observed,
                });
            }
        }
        // A cancellation can be observed while the VMM is running; its audit
        // event was inserted before this completed outcome arrived. Order by
        // monotonic host observations, never by wall-clock adjustment or append time.
        self.events.sort_by_key(|event| event.observed);
        for (index, event) in self.events.iter_mut().enumerate() {
            event.sequence = index;
        }
        self.execution = Some(Execution {
            cell_id: outcome.cell_id.clone(),
            substrate: outcome.substrate.clone(),
            pilot: outcome.execution.clone(),
            granted: outcome
                .execution
                .as_ref()
                .map(|_| request.capabilities.clone()),
            inputs: outcome.input_hashes.clone(),
            broker: outcome.broker.clone(),
            exit_code: outcome.exit_code,
            signal: outcome.signal,
            watchdog_stopped: outcome.timed_out,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_excludes_request_payloads_and_unacknowledged_authority() {
        let mut request: ExecutionRequest =
            serde_json::from_str(include_str!("../../../examples/execution/forge-task.json"))
                .unwrap();
        request.forge.as_mut().unwrap().task = "DO_NOT_LOG_TASK_OR_SECRET".into();
        let mut audit = Audit::new(&request, "node-a");
        let outcome = LaunchOutcome {
            execution: None,
            substrate: None,
            broker: Default::default(),
            lifecycle: vec![],
            input_hashes: vec![],
            cell_id: "cell-a".into(),
            output: Some(b"DO_NOT_LOG_OUTPUT".to_vec()),
            denial: Some("DO_NOT_LOG_DIAGNOSTIC".into()),
            exit_code: None,
            signal: None,
            timed_out: false,
        };
        audit.executed(&request, &outcome);
        audit.phase("Failed");
        let value = serde_json::to_value(&audit).unwrap();
        assert!(value["execution"]["granted"].is_null());
        assert!(value["execution"]["pilot"].is_null());
        let text = value.to_string();
        assert!(!text.contains("DO_NOT_LOG"));
        assert_eq!(value["caller"], request.workload.caller);
        assert_eq!(value["execution"]["cellId"], "cell-a");
        for _ in 0..100 {
            audit.phase("Failed");
        }
        assert_eq!(audit.events.len(), 2);
    }

    #[test]
    fn delayed_cell_events_are_ordered_before_cancellation_by_observation() {
        let request: ExecutionRequest =
            serde_json::from_str(include_str!("../../../examples/execution/forge-task.json"))
                .unwrap();
        let mut audit = Audit::new(&request, "node");
        let running = crate::dispatch::CellEvent {
            phase: "CellRunning".into(),
            at: crate::dispatch::now_rfc3339(),
            observed: std::time::Instant::now(),
        };
        audit.phase("Cancelling");
        let dissolved = crate::dispatch::CellEvent {
            phase: "Dissolved".into(),
            at: crate::dispatch::now_rfc3339(),
            observed: std::time::Instant::now(),
        };
        let outcome = LaunchOutcome {
            execution: None,
            substrate: None,
            broker: Default::default(),
            lifecycle: vec![running, dissolved],
            input_hashes: vec![],
            cell_id: "cell".into(),
            output: None,
            denial: None,
            exit_code: None,
            signal: None,
            timed_out: true,
        };
        audit.executed(&request, &outcome);
        assert_eq!(
            audit
                .events
                .iter()
                .map(|event| event.phase.as_str())
                .collect::<Vec<_>>(),
            ["Admitting", "CellRunning", "Cancelling", "Dissolved"]
        );
        assert_eq!(
            audit
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
    }
}
