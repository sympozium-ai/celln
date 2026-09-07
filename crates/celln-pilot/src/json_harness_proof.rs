//! Explicit KVM functional proof: scripted by default; --real-model is billable.
use anyhow::{ensure, Context, Result};
use celln_manifest::{
    closure::{Closure, Member},
    Author, Entry, Hash, Manifest, Tier,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::Command,
    time::Duration,
};
use warden::vmm::boot::{BootConfig, BootEnd, LinuxCell};

fn main() -> Result<()> {
    let real_model = std::env::args().any(|arg| arg == "--real-model");
    let package_only = std::env::args().any(|arg| arg == "--package-only");
    ensure!(
        !(real_model && package_only),
        "choose real-model or package-only, not both"
    );
    let token = if real_model {
        Some(PathBuf::from(
            std::env::var_os("CELLN_MODEL_TOKEN_FILE")
                .context("real model requires explicit host credential file")?,
        ))
    } else {
        None
    };
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binaries = PathBuf::from(
        std::env::var_os("CELLN_PILOT_DIR")
            .context("explicit static guest binary directory required")?,
    );
    let work = root.join(format!("target/json-harness-proof-{}", std::process::id()));
    std::fs::create_dir(&work)?;
    std::fs::copy(binaries.join("celln-harness-json"), work.join("harness"))?;
    for (name, fixture, uppercase) in [
        ("pilot-fetch", "json_broker.rs", false),
        ("uppercase", "json_tool.rs", true),
        ("length", "json_tool.rs", false),
    ] {
        if (real_model || package_only) && name == "pilot-fetch" {
            std::fs::copy(binaries.join("pilot-fetch"), work.join(name))?;
            continue;
        }
        let mut build = Command::new("rustc");
        build.args([
            "--edition=2021",
            "-O",
            "--target",
            "x86_64-unknown-linux-musl",
        ]);
        if uppercase {
            build.args(["--cfg", "uppercase_tool"]);
        }
        ensure!(
            build
                .arg(root.join("crates/celln-pilot/tests/fixtures").join(fixture))
                .arg("-o")
                .arg(work.join(name))
                .status()?
                .success(),
            "fixture build failed"
        );
    }
    std::fs::copy(work.join("uppercase"), work.join("unselected"))?;
    let mut mk = Command::new(root.join("scripts/mktoolfs.sh"));
    mk.arg(work.join("toolfs.img")).arg("32");
    for name in [
        "harness",
        "pilot-fetch",
        "uppercase",
        "length",
        "unselected",
    ] {
        mk.arg(work.join(name));
    }
    ensure!(mk.status()?.success(), "filesystem build failed");
    let payload = std::fs::read(work.join("toolfs.img"))?;
    let mut members = BTreeMap::new();
    for name in ["harness", "pilot-fetch", "uppercase", "length"] {
        members.insert(
            format!("/{name}"),
            Member {
                hash: Hash::of(&std::fs::read(work.join(name))?).0,
                dependencies: BTreeSet::new(),
            },
        );
    }
    members.get_mut("/harness").unwrap().dependencies = ["/pilot-fetch", "/uppercase", "/length"]
        .into_iter()
        .map(String::from)
        .collect();
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        toolfs: Hash::of(&payload).0,
        entrypoint: "/harness".into(),
        interpreter: false,
        members: members.clone(),
    }
    .sign(&[42; 32])
    .map_err(anyhow::Error::msg)?;
    signed
        .verify(&BTreeSet::from([signed.publisher.clone()]))
        .map_err(anyhow::Error::msg)?;
    std::fs::write(
        work.join("signed-closure.json"),
        serde_json::to_vec(&signed)?,
    )?;
    let mut manifest = Manifest::new();
    manifest.admit(Entry {
        alias: "/harness".into(),
        hash: Hash(members["/harness"].hash.clone()),
        tier: Tier::Verified,
        interpreter: false,
        author: Author::Host,
        recipe: None,
    });
    manifest.sign_standin();
    std::fs::write(work.join("manifest.json"), serde_json::to_vec(&manifest)?)?;
    ensure!(
        Command::new(root.join("scripts/mkinitramfs.sh"))
            .current_dir(&root)
            .arg(work.join("initramfs.cpio"))
            .env("CELLN_MANIFEST", work.join("manifest.json"))
            .env("CELLN_PILOT_DIR", &binaries)
            .env("CELLN_WARM_DISPATCH", "1")
            .env_remove("CELLN_RUN_JSON")
            .status()?
            .success(),
        "initrd build failed"
    );
    if package_only {
        println!("PACKAGED: native JSON Harness with real broker client; no model call or KVM execution; {}", work.display());
        return Ok(());
    }
    let kernel = BootConfig::host_kernel().context("readable kernel required")?;
    let mut template = LinuxCell::boot(
        BootConfig::new(kernel)
            .with_pmem(payload.len())
            .with_initrd(work.join("initramfs.cpio")),
    )?;
    template.seal_tool(&Hash::of(&payload), &payload)?;
    template.stop_when_guest_prints("CELLN:mote=parked");
    ensure!(
        template.run()?.end == BootEnd::Parked,
        "warm mote did not park"
    );
    let mote = template.park()?;
    drop(template);
    let input = r#"{"type":"object","properties":{"text":{"type":"string","minLength":1,"maxLength":64}},"required":["text"],"additionalProperties":false}"#;
    let length = r#"{"type":"object","properties":{"length":{"type":"integer","minimum":0,"maximum":64}},"required":["length"],"additionalProperties":false}"#;
    let schema = |s: &str| json!({"bytes":s,"hash":Hash::of(s.as_bytes()).0});
    let mut cases = Vec::new();
    let mut model_calls = 0;
    for (task, expected) in [
        ("normalize then measure", "CELLN has length 5"),
        ("undeclared", "unselected tool requested"),
        ("invalid-arguments", "tool value type mismatch"),
        ("bad-result", "required tool field missing"),
        ("sleep", "tool deadline exceeded"),
        ("flood", "child output exceeded limit"),
        ("last-turn", "model budget leaves no tool result turn"),
    ] {
        if real_model && task != "normalize then measure" {
            continue;
        }
        let mut config = json!({"contract":"celln.json-tools/v1","task":task,"system":"Use the explicitly lent tools.","url":"https://example.invalid/chat/completions",
        "model":"scripted-not-ai","max_turns":6,"max_calls":6,"tools":[
            {"name":"uppercase","path":"/uppercase","hash":members["/uppercase"].hash,"description":"Uppercase text","input_schema":schema(input),"output_schema":schema(input),"input_bytes":1024,"output_bytes":256,"timeout_ms":100},
            {"name":"length","path":"/length","hash":members["/length"].hash,"description":"Measure text length","input_schema":schema(input),"output_schema":schema(length),"input_bytes":1024,"output_bytes":256,"timeout_ms":100}
        ]});
        if task == "last-turn" {
            config["max_turns"] = json!(1);
        }
        if real_model {
            config["url"] = json!("https://api.deepseek.com/chat/completions");
            config["model"] = json!("deepseek-chat");
            config["task"] = json!("Call uppercase with text celln, wait for its result, then call length with the uppercase result. Wait for both tool results. Finally answer exactly: CELLN has length 5");
        }
        let mut cell = LinuxCell::fork_from(&mote)?;
        if let Some(token) = &token {
            let mut policy = warden::egress::HttpPolicy::new(vec!["api.deepseek.com".into()]);
            policy.timeout = Duration::from_secs(45);
            policy.max_requests = 6;
            policy.json_posts.push(warden::egress::JsonPostGrant {
                url: "https://api.deepseek.com/chat/completions".into(),
                bearer_token_file: token.clone(),
                model: "deepseek-chat".into(),
                max_output_tokens: 512,
                max_total_output_tokens: 3072,
            });
            cell.enable_http_fetch(policy);
        }
        cell.set_invocation(&serde_json::to_vec(&json!({"path":"/harness","alias":"/harness","root":"/tools","args":[config.to_string()],"force_agent_lane":true,
            "expected_hash":members["/harness"].hash,"workspace_access":"none","report_output_limit":8192,"closure_members":members,"allow_fetch":real_model}))?)?;
        cell.set_timeout(Duration::from_secs(if real_model { 180 } else { 10 }));
        let report = cell.run()?;
        let activity = cell.fetch_activity();
        model_calls += activity.0;
        drop(cell);
        std::fs::write(
            work.join(format!("{}.console", task.replace(' ', "-"))),
            &report.console,
        )?;
        // Workload bytes are framed as numeric arrays by pilot; decode outputs
        // before inspecting them, never accept workload text as control frames.
        let mut output = Vec::new();
        let mut exit = None;
        for line in report
            .console
            .lines()
            .filter_map(|l| l.strip_prefix(pilot::dispatch_report::PREFIX))
        {
            match serde_json::from_str::<pilot::dispatch_report::Frame>(line)? {
                pilot::dispatch_report::Frame::Output { bytes } => output.extend(bytes),
                pilot::dispatch_report::Frame::Exit { code } => exit = Some(code),
                _ => {}
            }
        }
        let output = String::from_utf8(output)?;
        if task == "last-turn" {
            ensure!(
                !output.contains("\"type\":\"tool\""),
                "last-turn batch emitted a completed tool event"
            );
        }
        if real_model {
            let events: Vec<serde_json::Value> = output
                .lines()
                .filter_map(|l| l.strip_prefix("CELLN_HARNESS_EVENT "))
                .map(serde_json::from_str)
                .collect::<std::result::Result<_, _>>()?;
            let tools: Vec<_> = events.iter().filter(|e| e["type"] == "tool").collect();
            ensure!(
                tools.len() == 2
                    && tools[0]["name"] == "uppercase"
                    && tools[0]["result"] == json!({"text":"CELLN"})
                    && tools[1]["name"] == "length"
                    && tools[1]["result"] == json!({"length":5})
                    && activity.0 >= 3
                    && activity.1 == 0,
                "real model did not consume both verified tool results: {output}; see {}",
                work.display()
            );
        }
        ensure!(
            report.end == BootEnd::Shutdown && output.contains(expected),
            "case {task} failed: {output}; see {}",
            work.display()
        );
        ensure!(
            exit == Some(if task == "normalize then measure" {
                0
            } else {
                1
            }),
            "unexpected exit for {task}: {exit:?}"
        );
        cases.push(json!({"task":task,"expected":expected,"exit":exit,"elapsedMicros":report.elapsed.as_micros(),"output":output}));
    }
    drop(mote);
    let evidence = json!({"status":"passed","scope":if real_model {"direct-KVM-native-JSON-adapter-real-DeepSeek-not-dispatcher"} else {"real-KVM-native-adapter-with-scripted-broker-not-AI"},"modelCalls":model_calls,"cases":cases,"closure":signed,
        "guestBinary":Hash::of(&std::fs::read(binaries.join("celln-harness-json"))?).0});
    std::fs::write(
        work.join("evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!(
        "PASS: JSON Harness KVM proof (real model: {real_model}); evidence {}",
        work.display()
    );
    Ok(())
}
