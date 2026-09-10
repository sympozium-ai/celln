//! Explicit deterministic native-parent/child handoff test. Not production
//! authorization, a durable owner, or real-model proof.
use anyhow::{ensure, Context, Result};
use celln_manifest::Hash;
use serde_json::{json, Value};
use std::{path::PathBuf, time::Duration};
use warden::{
    parent_lease::{ParentLease, TurnLimits},
    vmm::boot::{BootEnd, LinuxCell, Mote},
};

fn exchange(parent: &mut LinuxCell, message: Value) -> Result<Value> {
    parent.deliver_parent_message(&serde_json::to_vec(&message)?)?;
    let report = parent.run()?;
    ensure!(
        report.end == BootEnd::Parked,
        "native parent failed: {}",
        report.tail(30)
    );
    ensure!(!report.console.contains("Linux version"), "parent hot boot");
    Ok(serde_json::from_slice(
        &parent
            .take_parent_response()?
            .context("missing parent response")?,
    )?)
}

fn model_template(work: &std::path::Path, borrowed: bool) -> Result<pilot::turn_worker::Template> {
    let mut config = json!({"contract":"celln.json-tools/v1", "task":"",
        "system":"Answer briefly, in at most ten words. Remember user-provided values across the supplied conversation.",
        "url":"https://api.deepseek.com/chat/completions", "model":"deepseek-chat", "tools":[], "max_turns":1,"max_calls":0});
    if borrowed {
        let schema = r#"{"type":"object","properties":{"text":{"type":"string","minLength":1,"maxLength":64}},"required":["text"],"additionalProperties":false}"#;
        config["tools"] = json!([{"name":"uppercase","path":"/uppercase","hash":Hash::of(&std::fs::read(work.join("uppercase"))?).0,
            "description":"Uppercase text", "input_schema":{"bytes":schema,"hash":Hash::of(schema.as_bytes()).0},
            "output_schema":{"bytes":schema,"hash":Hash::of(schema.as_bytes()).0}, "input_bytes":1024,"output_bytes":256,"timeout_ms":1000}]);
        config["max_turns"] = json!(3);
        config["max_calls"] = json!(1);
    }
    pilot::turn_worker::Template::new(serde_json::from_value(config)?)
}

pub fn run(
    mut parent: LinuxCell,
    mote: Mote,
    worker: Hash,
    work: PathBuf,
    token: Option<PathBuf>,
    borrowed: bool,
    cancel_child: bool,
) -> Result<()> {
    let real = token.is_some();
    let template = if real {
        Some(model_template(&work, borrowed)?)
    } else {
        None
    };
    let first = if cancel_child {
        "block-child"
    } else if borrowed {
        "My value is violet. Call uppercase with my value and answer only the tool result text."
    } else {
        "my value is violet"
    };
    let second = if borrowed {
        "Call uppercase on my original value again. Answer only the tool result text."
    } else {
        "repeat my value"
    };
    let evidence = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let owner_evidence = evidence.clone();
    let owner_work = work.clone();
    let owner =
        warden::parent_registry::ParentRegistry::new(1, 1 << 30).map_err(anyhow::Error::msg)?;
    let incarnation = Hash::of(work.as_os_str().as_encoded_bytes());
    pilot::parent_session::spawn_registered(
        &owner,
        "local-proof",
        &incarnation,
        Duration::from_secs(180),
        1 << 30,
        move || {
            let work = owner_work;
            let parent_id = Hash::of(work.as_os_str().as_encoded_bytes());
            let journal = warden::parent_journal::ParentJournal::create(
                &work.join("parent-journal"),
                parent_id.clone(),
            )?;
            let lease = ParentLease::new(
                parent_id,
                Duration::from_secs(180),
                TurnLimits {
                    memory_bytes: 256 << 20,
                    timeout: Duration::from_secs(if real { 60 } else { 10 }),
                    model_requests: if borrowed {
                        3
                    } else if real {
                        1
                    } else {
                        0
                    },
                    output_tokens: if borrowed {
                        1536
                    } else if real {
                        512
                    } else {
                        0
                    },
                },
                2,
                if borrowed {
                    6
                } else if real {
                    2
                } else {
                    0
                },
                if borrowed {
                    3072
                } else if real {
                    1024
                } else {
                    0
                },
            )?;
            let mut previous_answer = String::new();
            let parent_transport = move |bytes: &[u8]| -> Result<Vec<u8>> {
                Ok(serde_json::to_vec(&exchange(
                    &mut parent,
                    serde_json::from_slice(bytes)?,
                )?)?)
            };
            let worker_transport = move |reservation: &warden::parent_lease::ReservedTurn| -> Result<pilot::parent_session::DestroyedChild> {
        let id = reservation.request.turn_id.as_str();
        let task: Value = serde_json::from_str(&reservation.request.task)?;
        if id == "two" {
            ensure!(
                task["history"][0]["user"] == first,
                "parent lost user context"
            );
            ensure!(
                task["history"][0]["assistant"] == previous_answer,
                "parent lost real child result"
            );
        }
        let worker_args = template.as_ref().map(|t| t.arguments(reservation)).transpose()?;
        let mut child = LinuxCell::fork_from(&mote)?;
        child.set_timeout(reservation.limits.timeout);
        let mut invocation = json!({"path":"/worker", "alias":"/worker", "root":"/tools",
            "args":[reservation.request.task], "force_agent_lane":true, "expected_hash":worker.0,
            "workspace_access":"none", "report_output_limit":8192,
            "closure_members":{"/worker":{"hash":worker.0,"dependencies":[]}}});
        if let Some(token) = token.as_deref() {
            invocation["allow_fetch"] = json!(true);
            invocation["closure_members"]["/worker"]["dependencies"] = json!(["/pilot-fetch"]);
            invocation["closure_members"]["/pilot-fetch"] = json!({"hash":Hash::of(&std::fs::read(work.join("pilot-fetch"))?).0,"dependencies":[]});
            if borrowed {
                let tool_hash = Hash::of(&std::fs::read(work.join("uppercase"))?).0;
                invocation["closure_members"]["/worker"]["dependencies"] =
                    json!(["/pilot-fetch", "/uppercase"]);
                invocation["closure_members"]["/uppercase"] =
                    json!({"hash":tool_hash,"dependencies":[]});
            }
            invocation["args"] = json!(worker_args.context("missing worker template arguments")?);
            let mut policy = warden::egress::HttpPolicy::new(vec!["api.deepseek.com".into()]);
            policy.timeout = Duration::from_secs(45);
            policy.max_requests = reservation.limits.model_requests as usize;
            policy.json_posts.push(warden::egress::JsonPostGrant {
                protocol: Default::default(),
                url: "https://api.deepseek.com/chat/completions".into(),
                bearer_token_file: token.into(),
                model: "deepseek-chat".into(),
                max_output_tokens: 512,
                max_total_output_tokens: reservation.limits.output_tokens,
            });
            child.enable_http_fetch(policy);
        }
        child.set_invocation(&serde_json::to_vec(&invocation)?)?;
        let report = child.run()?;
        if cancel_child {
            std::fs::write(work.join("cancelled-child.console"), &report.console)?;
            ensure!(report.end == BootEnd::TimedOut, "busy child was not interrupted");
            let mut observed = Vec::new();
            for line in report.console.lines().filter_map(|l| l.strip_prefix(pilot::dispatch_report::PREFIX)) {
                if let pilot::dispatch_report::Frame::Output { bytes } = serde_json::from_str(line)? { observed.extend(bytes); }
            }
            ensure!(String::from_utf8(observed)?.contains("CHILD_BUSY_ENTERED"), "child never entered busy loop");
            drop(child);
            anyhow::bail!("busy child stopped and destroyed");
        }
        ensure!(
            report.end == BootEnd::Shutdown,
            "child failed: {}",
            report.tail(30)
        );
        ensure!(!report.console.contains("Linux version"), "child hot boot");
        let mut output = Vec::new();
        let mut exited = false;
        let mut checked = false;
        for line in report
            .console
            .lines()
            .filter_map(|l| l.strip_prefix(pilot::dispatch_report::PREFIX))
        {
            match serde_json::from_str::<pilot::dispatch_report::Frame>(line)? {
                pilot::dispatch_report::Frame::Started { grant } => {
                    ensure!(
                        grant.tool == worker.0
                            && grant.fetch == real
                            && grant.workspace.as_deref() == Some("none"),
                        "child grant mismatch"
                    );
                    checked = true;
                }
                pilot::dispatch_report::Frame::Output { bytes } => output.extend(bytes),
                pilot::dispatch_report::Frame::Exit { code } => {
                    ensure!(code == 0, "child exit failure");
                    exited = true;
                }
                pilot::dispatch_report::Frame::Failed { .. }
                | pilot::dispatch_report::Frame::Signal { .. } => {
                    anyhow::bail!("child execution failed")
                }
                _ => {}
            }
        }
        ensure!(checked && exited, "missing child hash/exit evidence");
        if !real {
            ensure!(
                output == reservation.request.task.as_bytes(),
                "deterministic child output mismatch"
            );
        }
        std::fs::write(work.join(format!("child-{id}.console")), &report.console)?;
        let model_activity = child.fetch_activity();
        drop(child);
        let output = String::from_utf8(output)?;
        let answer = if real {
            ensure!(
                model_activity.0 == if borrowed { 2 } else { 1 },
                "unexpected real model request count"
            );
            let events: Vec<Value> = output
                .lines()
                .filter_map(|l| l.strip_prefix("CELLN_HARNESS_EVENT "))
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?;
            let completed = events
                .iter()
                .find(|e| e["type"] == "completed")
                .context("no model completion")?;
            if borrowed {
                let tool_events: Vec<_> = events
                    .iter()
                    .filter(|event| event["type"] == "tool")
                    .collect();
                ensure!(
                    tool_events.len() == 1 && tool_events[0]["name"] == "uppercase",
                    "missing selected tool execution"
                );
                ensure!(completed["calls"] == 1, "tool call count mismatch");
            }
            let answer = completed["answer"]
                .as_str()
                .context("no model answer")?
                .to_string();
            if id == "two" {
                ensure!(
                    answer.to_lowercase().contains("violet"),
                    "model did not recall retained context"
                );
            }
            if borrowed {
                ensure!(
                    answer.trim() == "VIOLET",
                    "model did not return borrowed tool result"
                );
            }
            answer
        } else {
            output
        };

        previous_answer = answer.clone();
        owner_evidence.lock().expect("proof evidence lock").push(json!({"parent":reservation.parent.0,"child":reservation.child.0,"turn":id,"worker":worker.0,
            "request":{"kind":"spawn","request":reservation.request},"modelRequests":model_activity.0,
            "realModel":real,"borrowedUppercase":borrowed,"childDestroyedBeforeCommit":true,
            "workerTemplate":template.as_ref().map(|t| &t.binding().0)}));
        Ok(pilot::parent_session::DestroyedChild { child:reservation.child.clone(), succeeded:true, answer })
    };
            Ok(pilot::parent_session::ParentSession::new(
                parent_transport,
                worker_transport,
                lease,
                journal,
            ))
        },
    )?;
    let mut completed_results = Vec::new();
    for (id, message) in [("one", first), ("two", second)] {
        let pending = owner
            .submit(
                "local-proof",
                &incarnation,
                &serde_json::to_vec(
                    &json!({"kind":"turn","apiVersion":pilot::parent_harness::VERSION,
            "turnId":id,"message":message}),
                )?,
            )
            .map_err(anyhow::Error::msg)?;
        if cancel_child {
            std::thread::sleep(Duration::from_secs(1));
            owner
                .cancel("local-proof", &incarnation)
                .map_err(anyhow::Error::msg)?;
            let result = pending.recv_timeout(Duration::from_secs(3))?;
            ensure!(
                result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e == "busy child stopped and destroyed"),
                "cancellation proof failed: {result:?}"
            );
            owner
                .stop("local-proof", &incarnation)
                .map_err(anyhow::Error::msg)?;
            ensure!(
                matches!(
                    warden::parent_journal::inspect_turn(
                        &work.join("parent-journal"),
                        &Hash::of(work.as_os_str().as_encoded_bytes()),
                        id
                    )?,
                    warden::parent_journal::TurnStatus::Reserved(_)
                ),
                "cancelled child must not have a durable result acknowledgement"
            );
            std::fs::write(
                work.join("cancelled-tree.json"),
                serde_json::to_vec_pretty(&json!({
                    "guestBusyObserved":true, "childInterrupted":true, "childDestroyed":true,
                    "parentOwnerJoined":true, "resultCommitted":false,
                    "durableStage":"reserved", "liveContext":"lost"
                }))?,
            )?;
            println!("PASS: busy child observed and interrupted, child dropped, parent owner joined. Evidence: {}", work.display());
            return Ok(());
        }
        let reply = pending
            .recv_timeout(Duration::from_secs(90))?
            .map_err(anyhow::Error::msg)?;
        completed_results.push(serde_json::from_slice::<Value>(&reply)?);
    }
    owner
        .stop("local-proof", &incarnation)
        .map_err(anyhow::Error::msg)?;
    let mut evidence = evidence.lock().expect("proof evidence lock");
    ensure!(
        evidence[0]["child"] != evidence[1]["child"],
        "child identity reused"
    );
    for (record, result) in evidence.iter_mut().zip(completed_results) {
        let status = warden::parent_journal::inspect_turn(
            &work.join("parent-journal"),
            &Hash::of(work.as_os_str().as_encoded_bytes()),
            record["turn"].as_str().context("missing turn identity")?,
        )?;
        let warden::parent_journal::TurnStatus::ParentCommitted(durable) = status else {
            anyhow::bail!("missing durable parent acknowledgement after owner shutdown");
        };
        ensure!(
            durable.child.0 == record["child"]
                && durable.succeeded == result["succeeded"]
                && durable.answer == result["answer"],
            "durable result mismatch"
        );
        record["result"] = result;
        record["durableStage"] = json!("parent-committed");
        record["liveContext"] = json!("lost");
    }
    std::fs::write(
        work.join("native-turns.json"),
        serde_json::to_vec_pretty(&*evidence)?,
    )?;
    println!("PASS: composed native session, two distinct sealed child VMs, retained context, journaled commits, all VMs dropped. realModel={real}; NOT production admission. Evidence: {}", work.display());
    Ok(())
}
