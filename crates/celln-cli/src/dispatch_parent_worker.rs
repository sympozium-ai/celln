//! Declared native worker: fixed signed closure + host policy, forked per turn.
use super::*;
use celln_manifest::Hash;
use pilot::turn_worker::Template;
use warden::{parent_lease::ReservedTurn, parent_permit::Binding};

pub(super) struct PreparedWorker {
    declared: PreparedDeclared,
    request: ExecutionRequest,
    binding: Binding,
    template: Template,
    brokers: super::parent_model::ChildBrokers,
    root: std::path::PathBuf,
}

fn check_tools(
    closure: &celln_manifest::closure::Closure,
    template: &Template,
) -> Result<(), String> {
    let tools = &template.policy().tools;
    if closure.entrypoint == "/pilot-fetch" || !closure.members.contains_key("/pilot-fetch") {
        return Err("worker lacks admitted broker helper".into());
    }
    if closure.sources.is_empty() {
        let mut expected =
            std::collections::BTreeSet::from([closure.entrypoint.as_str(), "/pilot-fetch"]);
        for tool in tools {
            if !expected.insert(&tool.path)
                || !closure
                    .members
                    .get(&tool.path)
                    .is_some_and(|m| m.hash == tool.hash)
            {
                return Err("borrowed tool does not match worker closure".into());
            }
        }
        if closure
            .members
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected
        {
            return Err("worker closure contains unselected executable members".into());
        }
    } else {
        closure.validate()?;
        if closure.sources.len() != tools.len() + 1 {
            return Err("worker composition does not match tool selection".into());
        }
        let runtime = closure.sources[0].parse()?.closure;
        if runtime.entrypoint != closure.entrypoint || !runtime.members.contains_key("/pilot-fetch")
        {
            return Err("worker runtime does not own entrypoint and broker".into());
        }
        for (source, tool) in closure.sources.iter().skip(1).zip(tools) {
            let source = source.parse()?.closure;
            if source.entrypoint != tool.path
                || source.members[&source.entrypoint].hash != tool.hash
            {
                return Err("borrowed tool composition root mismatch".into());
            }
        }
    }
    Ok(())
}

pub(super) fn prepare_worker(
    request: &ExecutionRequest,
    template: Template,
    profile: Hash,
    binding: &Binding,
    mote_root: &Path,
    tool_root: &Path,
    state_root: &Path,
) -> Result<PreparedWorker, String> {
    if request.harness.is_some()
        || request.forge.is_some()
        || !request.inputs.is_empty()
        || !request.capabilities.egress.is_empty()
        || request.capabilities.workspace != celln_spec::WorkspaceAccess::None
        || request.execution.lane != celln_spec::RequestedLane::Agent
        || !request.execution.require_hardware_isolation
        || request.capabilities.memory_bytes != binding.child_memory_bytes
        || request.capabilities.timeout_ms != binding.turn_timeout_ms
        || request.tools.len() != 1
        || request.tools[0].closure.is_none()
        || !request
            .invocation
            .as_ref()
            .is_some_and(|i| i.args.is_empty())
    {
        return Err("worker request exceeds native turn contract".into());
    }
    let brokers = super::parent_model::ChildBrokers::new(
        state_root,
        profile,
        binding.clone(),
        request,
        &template,
    )?;
    let declared = prepare_declared(request, mote_root, tool_root, state_root)?;
    let closure = super::super::closure::resolve(request, &declared.resolved, state_root)?
        .ok_or("worker needs signed closure")?;
    check_tools(&closure.signed.closure, &template)?;
    Ok(PreparedWorker {
        declared,
        request: request.clone(),
        binding: binding.clone(),
        template,
        brokers,
        root: state_root.into(),
    })
}

impl PreparedWorker {
    pub(super) fn matches_parent(&self, binding: &Binding) -> bool {
        &self.binding == binding
    }
    /// ParentSession must already have durably reserved this turn. The complete
    /// cell owner is consumed/dropped by run_cell before this returns a result.
    pub(super) fn execute(
        &mut self,
        turn: &ReservedTurn,
    ) -> Result<pilot::parent_session::DestroyedChild, String> {
        let audit_directory = parent_audit_directory(&self.root)?;
        #[cfg(test)]
        let audit_directory = audit_directory.or_else(|| Some(self.root.clone()));
        if turn.parent != self.binding.incarnation
            || turn.limits.memory_bytes != self.binding.child_memory_bytes
        {
            return Err("worker reservation does not match pinned memory or parent".into());
        }
        // A turn whose context the admitted template refuses never starts a
        // child: no cell exists for it, and the parent's context is intact.
        // It is a failed turn the caller can read, not a lost parent.
        let args = match self.template.arguments(turn) {
            Ok(args) => args,
            Err(error) => {
                return Ok(pilot::parent_session::DestroyedChild {
                    child: turn.child.clone(),
                    succeeded: false,
                    answer: bounded_failure(format!("Turn failed; no worker started: {error:#}")),
                })
            }
        };
        authorize(&self.request, &self.root)?;
        let closure =
            super::super::closure::resolve(&self.request, &self.declared.resolved, &self.root)?
                .ok_or("worker closure unavailable")?;
        check_tools(&closure.signed.closure, &self.template)?;
        for member in closure.signed.closure.members.values() {
            local_agent_constraint(&member.hash, &self.root)?;
        }
        let mut broker = self.brokers.for_turn(turn)?;
        // Kept through the owned VM execution; any exit revokes all grant copies.
        let _workspace_lease = self.brokers.workspace_for_turn(turn, &mut broker)?;
        let mut invocation: serde_json::Value =
            serde_json::from_slice(&self.declared.invocation).map_err(|e| e.to_string())?;
        invocation["args"] = serde_json::json!(args);
        invocation["allow_fetch"] = serde_json::json!(true);
        let invocation = serde_json::to_vec(&invocation).map_err(|e| e.to_string())?;
        if invocation.len() > warden::MAX_INVOCATION_BYTES {
            return Err("worker invocation exceeds bound".into());
        }
        let mut cell = self.declared.mote.fork()?;
        cell.set_invocation(&invocation)
            .map_err(|e| e.to_string())?;
        let mut request = self.request.clone();
        request.id = turn.child.0.clone();
        request.workload.id = turn.child.0.clone();
        request.capabilities.timeout_ms = u64::try_from(turn.limits.timeout.as_millis())
            .map_err(|_| "worker timeout overflow")?;
        if request.capabilities.timeout_ms == 0 {
            return Err("remaining worker timeout is below execution resolution".into());
        }
        request.capabilities.egress = broker
            .allow_hosts
            .iter()
            .map(|host| format!("https://{host}"))
            .collect();
        let mut outcome = super::super::run_cell_with_broker(
            &request,
            &request.invocation.as_ref().unwrap().alias,
            cell,
            &self.root,
            Some(broker),
        )?;
        super::super::validate_executed_tool(&mut outcome, &self.declared.resolved.program_hash);
        // run_cell_with_broker returned only after dropping its owned VM.
        // Do not convert execution errors or authority-report mismatches into
        // a cancellation acknowledgement. Parent cancellation still prevents
        // the later parent-scope context commit.
        let cancelled = cancelled_after_teardown(
            outcome.denial.as_deref(),
            celln_control::current().and_then(|control| control.reason()),
        );
        // The child ran in its own cell; the parent's context is intact
        // whatever happened to it. A child that failed (a refused or failing
        // model request, a timeout, a crash) is a failed turn the caller can
        // read and follow up on, never lost parent context.
        let (succeeded, answer) = if cancelled {
            (false, "Turn cancelled after child teardown.".into())
        } else if let Some(reason) = failure_reason(&outcome) {
            (false, reason)
        } else {
            // The child is gone either way. An answer outside the contract
            // (missing, duplicated, oversized) fails this turn; it is never a
            // reason to lose the parent's context.
            match answer(outcome.output.as_deref().unwrap_or_default()) {
                Ok(answer) => (true, answer),
                Err(reason) => (
                    false,
                    bounded_failure(format!("Turn failed; no result committed: {reason}")),
                ),
            }
        };
        // Explicit host opt-in only: contains sensitive conversation/tool data,
        // never authority to replay. Default production operation retains none.
        if let Some(directory) = audit_directory {
            retain_audit(
                &directory,
                &turn.child,
                &serde_json::to_vec_pretty(&serde_json::json!({"broker":outcome.broker,
                "output":String::from_utf8_lossy(outcome.output.as_deref().unwrap_or_default()),
                "cancelled":cancelled,
                "succeeded":succeeded,
                "execution":outcome.execution}))
                .map_err(|e| e.to_string())?,
            )?;
        }
        Ok(pilot::parent_session::DestroyedChild {
            child: turn.child.clone(),
            succeeded,
            answer,
        })
    }
}

/// Bound on the failure text committed as a failed turn's answer.
const FAILURE_ANSWER_BYTES: usize = 1024;

/// Why a destroyed child produced no answer, with a bounded tail of what it
/// printed (typically the model refusal or provider error), or None when it
/// exited cleanly. Only called after the child's VM is gone.
fn failure_reason(outcome: &super::super::LaunchOutcome) -> Option<String> {
    let cause = if outcome.timed_out {
        "child timed out".to_string()
    } else if let Some(denial) = &outcome.denial {
        format!("child refused: {denial}")
    } else if let Some(signal) = outcome.signal {
        format!("child stopped by signal {signal}")
    } else if outcome.exit_code != Some(0) {
        match outcome.exit_code {
            Some(code) => format!("child exited with status {code}"),
            None => "child exited without a status".to_string(),
        }
    } else {
        return None;
    };
    let mut reason = format!("Turn failed; no result committed: {cause}");
    let printed: String = String::from_utf8_lossy(outcome.output.as_deref().unwrap_or_default())
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if !printed.is_empty() {
        reason.push_str(": ");
        reason.push_str(&printed);
    }
    Some(bounded_failure(reason))
}

fn bounded_failure(mut reason: String) -> String {
    if reason.len() > FAILURE_ANSWER_BYTES {
        let mut end = FAILURE_ANSWER_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    reason
}

// Only called on the successful, VM-destroyed return path of the executor.
fn cancelled_after_teardown(denial: Option<&str>, reason: Option<celln_control::Stopped>) -> bool {
    reason == Some(celln_control::Stopped::Cancelled) && denial == Some("execution cancelled")
}

#[test]
fn cancelled_result_requires_host_cancellation_without_authority_mismatch() {
    use celln_control::Stopped;
    assert!(cancelled_after_teardown(
        Some("execution cancelled"),
        Some(Stopped::Cancelled)
    ));
    for (denial, reason) in [
        (Some("execution cancelled"), None),
        (Some("execution cancelled"), Some(Stopped::Deadline)),
        (
            Some("executed tool report mismatch"),
            Some(Stopped::Cancelled),
        ),
        (None, Some(Stopped::Cancelled)),
    ] {
        assert!(!cancelled_after_teardown(denial, reason));
    }
}

fn parent_audit_directory(root: &Path) -> Result<Option<std::path::PathBuf>, String> {
    use std::os::unix::fs::PermissionsExt;
    let directory = root.join("parent-audit");
    let metadata = match std::fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("parent audit policy unavailable".into()),
    };
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("parent-audit must be an operator-private directory, not a symlink".into());
    }
    Ok(Some(directory))
}

fn retain_audit(directory: &Path, child: &Hash, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if bytes.len() > 262144 {
        return Err("parent audit exceeds bound".into());
    }
    let mut file = tempfile::NamedTempFile::new_in(directory).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist_noclobber(directory.join(format!("worker-proof-{}.json", &child.0[7..])))
        .map_err(|_| "parent audit publication refused; preserve turn identity")?;
    std::fs::File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())
}

#[test]
fn parent_audit_requires_private_opt_in_and_never_overwrites() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    assert!(parent_audit_directory(root.path()).unwrap().is_none());
    let directory = root.path().join("parent-audit");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(parent_audit_directory(root.path()).is_err());
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        parent_audit_directory(root.path()).unwrap(),
        Some(directory.clone())
    );
    let child = Hash::of(b"audit-child");
    retain_audit(&directory, &child, b"evidence").unwrap();
    let path = directory.join(format!("worker-proof-{}.json", &child.0[7..]));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(retain_audit(&directory, &child, b"replacement").is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"evidence");
    assert!(retain_audit(&directory, &Hash::of(b"oversized"), &vec![0; 262145]).is_err());
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    let other = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(directory, other.path().join("parent-audit")).unwrap();
    assert!(parent_audit_directory(other.path()).is_err());
}

/// Answer bound of a guest package built before the worker declared one. Its
/// parent refuses anything longer, so the host must not deliver more.
const LEGACY_ANSWER_BYTES: usize = 2048;

/// The worker's one completion. The bound is the host's 8 KiB contract, or
/// the smaller one the guest package was built with: a current worker states
/// `answerLimit` in its completion, an older one states nothing and is held
/// to the 2 KiB its parent accepts. The statement can only narrow the bound.
fn answer(output: &[u8]) -> Result<String, String> {
    let output = std::str::from_utf8(output).map_err(|_| "invalid native worker output")?;
    let mut answer = None;
    for line in output
        .lines()
        .filter_map(|l| l.strip_prefix("CELLN_HARNESS_EVENT "))
    {
        let event: serde_json::Value =
            serde_json::from_str(line).map_err(|_| "invalid native worker event")?;
        if event["type"] == "completed" {
            if answer.is_some() {
                return Err("duplicate worker completion".into());
            }
            let text = event["answer"].as_str().ok_or("missing worker answer")?;
            let limit = match event.get("answerLimit") {
                None => LEGACY_ANSWER_BYTES,
                Some(declared) => {
                    usize::try_from(declared.as_u64().ok_or("invalid worker answer limit")?)
                        .unwrap_or(usize::MAX)
                        .min(warden::parent_protocol::MAX_ANSWER_BYTES)
                }
            };
            if text.trim().is_empty() || text.contains('\0') {
                return Err("worker answer is empty or contains NUL".into());
            }
            if text.len() > limit {
                return Err(format!(
                    "worker answer of {} bytes exceeds the {limit}-byte parent contract",
                    text.len()
                ));
            }
            answer = Some(text.to_owned());
        }
    }
    answer.ok_or_else(|| "missing worker completion".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(exit_code: Option<i32>, output: &str) -> super::super::super::LaunchOutcome {
        super::super::super::LaunchOutcome {
            execution: None,
            substrate: None,
            broker: Default::default(),
            lifecycle: vec![],
            input_hashes: vec![],
            cell_id: "child".into(),
            output: Some(output.as_bytes().to_vec()),
            denial: None,
            exit_code,
            signal: None,
            timed_out: false,
        }
    }

    // A child that failed is a failed turn with a readable reason, never an
    // owner error: the parent's context survives a provider outage or a bad
    // credential and the caller can ask again.
    #[test]
    fn child_failure_is_a_failed_turn_with_its_printed_reason() {
        assert_eq!(failure_reason(&outcome(Some(0), "fine")), None);
        let failed = failure_reason(&outcome(
            Some(1),
            "model request failed: HTTP 503\nService is too busy.",
        ))
        .unwrap();
        assert_eq!(
            failed,
            "Turn failed; no result committed: child exited with status 1: model request failed: HTTP 503 Service is too busy."
        );
        let mut refused = outcome(Some(1), "");
        refused.denial = Some("provider credential unavailable".into());
        assert_eq!(
            failure_reason(&refused).unwrap(),
            "Turn failed; no result committed: child refused: provider credential unavailable"
        );
        let mut timed = outcome(None, "");
        timed.timed_out = true;
        assert!(failure_reason(&timed).unwrap().contains("child timed out"));
        let mut signalled = outcome(None, "\u{7}beep");
        signalled.signal = Some(9);
        assert_eq!(
            failure_reason(&signalled).unwrap(),
            "Turn failed; no result committed: child stopped by signal 9: beep"
        );
        let long = failure_reason(&outcome(Some(2), &"é".repeat(4000))).unwrap();
        assert!(long.len() <= FAILURE_ANSWER_BYTES && long.is_char_boundary(long.len()));
    }
    #[test]
    fn worker_closure_cannot_expand_or_substitute_borrowed_tools() {
        use celln_manifest::closure::{Closure, Member};
        let schema = r#"{"type":"object","properties":{"text":{"type":"string","minLength":1,"maxLength":64}},"required":["text"],"additionalProperties":false}"#;
        let tool_hash = Hash::of(b"borrowed").0;
        let template=Template::new(serde_json::from_value(serde_json::json!({
            "contract":"celln.json-tools/v1","task":"","system":"host persona",
            "url":"https://api.deepseek.com/chat/completions","model":"deepseek-chat",
            "max_turns":2,"max_calls":1,"tools":[{"name":"borrowed","path":"/borrowed","hash":tool_hash,
                "description":"selected tool","input_schema":{"bytes":schema,"hash":Hash::of(schema.as_bytes()).0},
                "output_schema":{"bytes":schema,"hash":Hash::of(schema.as_bytes()).0},
                "input_bytes":1024,"output_bytes":1024,"timeout_ms":1000}]
        })).unwrap()).unwrap();
        let mut closure = Closure {
            api_version: "celln.dev/closure-v1".into(),
            sources: vec![],
            toolfs: Hash::of(b"image").0,
            entrypoint: "/worker".into(),
            interpreter: false,
            members: std::collections::BTreeMap::from([
                (
                    "/worker".into(),
                    Member {
                        hash: Hash::of(b"worker").0,
                        dependencies: Default::default(),
                    },
                ),
                (
                    "/pilot-fetch".into(),
                    Member {
                        hash: Hash::of(b"fetch").0,
                        dependencies: Default::default(),
                    },
                ),
                (
                    "/borrowed".into(),
                    Member {
                        hash: tool_hash.clone(),
                        dependencies: Default::default(),
                    },
                ),
            ]),
        };
        assert!(check_tools(&closure, &template).is_ok());
        closure.members.get_mut("/borrowed").unwrap().hash = Hash::of(b"substitute").0;
        assert!(check_tools(&closure, &template).is_err());
        closure.members.get_mut("/borrowed").unwrap().hash = tool_hash;
        closure.members.insert(
            "/extra".into(),
            Member {
                hash: Hash::of(b"extra").0,
                dependencies: Default::default(),
            },
        );
        assert!(check_tools(&closure, &template).is_err());
        closure.members.remove("/extra");
        closure.members.remove("/pilot-fetch");
        assert!(check_tools(&closure, &template).is_err());
    }
    #[test]
    fn completion_is_unique_bounded_and_requires_structured_event() {
        assert_eq!(
            answer(b"CELLN_HARNESS_EVENT {\"type\":\"completed\",\"answer\":\"hello\"}\n").unwrap(),
            "hello"
        );
        for output in [
            "hello",
            "CELLN_HARNESS_EVENT {}",
            "CELLN_HARNESS_EVENT {\"type\":\"completed\",\"answer\":\"\"}",
        ] {
            assert!(answer(output.as_bytes()).is_err());
        }
        let event = "CELLN_HARNESS_EVENT {\"type\":\"completed\",\"answer\":\"hello\"}\n";
        assert!(answer(event.repeat(2).as_bytes()).is_err());
    }
    #[test]
    fn answer_bound_is_eight_kibibytes_for_a_current_guest_and_two_for_an_old_one() {
        let completed = |bytes: usize, limit: Option<serde_json::Value>| {
            let mut event =
                serde_json::json!({"type":"completed","answer":"a".repeat(bytes),"calls":0});
            if let Some(limit) = limit {
                event["answerLimit"] = limit;
            }
            answer(format!("CELLN_HARNESS_EVENT {event}\n").as_bytes())
        };
        let current = || Some(serde_json::json!(8192));
        assert_eq!(completed(8192, current()).unwrap().len(), 8192);
        assert_eq!(
            completed(8193, current()).unwrap_err(),
            "worker answer of 8193 bytes exceeds the 8192-byte parent contract"
        );
        // A package built before the limit was stated has a 2 KiB parent.
        assert_eq!(completed(2048, None).unwrap().len(), 2048);
        assert!(completed(2049, None).unwrap_err().contains("2048-byte"));
        // The statement narrows the host bound and never widens it.
        assert!(completed(4097, Some(serde_json::json!(4096))).is_err());
        assert!(completed(8193, Some(serde_json::json!(1u64 << 40))).is_err());
        assert!(completed(8192, Some(serde_json::json!(1u64 << 40))).is_ok());
        assert!(completed(1, Some(serde_json::json!("8192"))).is_err());
        // Whatever the reason, it is a bounded failed-turn text.
        let reason = bounded_failure(format!("Turn failed: {}", "é".repeat(4000)));
        assert!(reason.len() <= FAILURE_ANSWER_BYTES && reason.is_char_boundary(reason.len()));
    }
}
