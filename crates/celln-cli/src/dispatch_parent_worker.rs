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
        let args = self.template.arguments(turn).map_err(|e| e.to_string())?;
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
            Some(warden::egress::HttpBroker::new(broker)),
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
        let answer = if cancelled {
            "Turn cancelled after child teardown.".into()
        } else {
            if outcome.denial.is_some() || outcome.timed_out || outcome.exit_code != Some(0) {
                return Err("native worker failed; child torn down, no result committed".into());
            }
            answer(
                outcome
                    .output
                    .as_deref()
                    .ok_or("missing native worker output")?,
            )?
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
                "execution":outcome.execution}))
                .map_err(|e| e.to_string())?,
            )?;
        }
        Ok(pilot::parent_session::DestroyedChild {
            child: turn.child.clone(),
            succeeded: !cancelled,
            answer,
        })
    }
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
            if text.trim().is_empty() || text.len() > 2048 || text.contains('\0') {
                return Err("worker answer exceeds parent contract".into());
            }
            answer = Some(text.to_owned());
        }
    }
    answer.ok_or_else(|| "missing worker completion".into())
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
