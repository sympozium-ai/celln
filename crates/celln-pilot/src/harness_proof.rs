//! Opt-in real-model, warm-fork reference Harness proof. Not a dispatcher adapter.
use anyhow::{ensure, Context, Result};
use celln_manifest::{
    closure::{Closure, Member},
    Author, Entry, Hash, Manifest, Tier,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::PathBuf,
    process::Command,
    time::Duration,
};
use warden::{
    egress::{HttpPolicy, JsonPostGrant},
    vmm::boot::{BootConfig, BootEnd, LinuxCell},
};

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binaries = PathBuf::from(
        std::env::var_os("CELLN_PILOT_DIR")
            .context("set CELLN_PILOT_DIR to static guest binaries")?,
    );
    let token = PathBuf::from(
        std::env::var_os("CELLN_MODEL_TOKEN_FILE")
            .context("set CELLN_MODEL_TOKEN_FILE to a private host credential file")?,
    );
    let work = std::env::temp_dir().join(format!("celln-harness-proof-{}", std::process::id()));
    std::fs::create_dir(&work)?;
    std::fs::copy(
        binaries.join("celln-harness-reference"),
        work.join("harness"),
    )?;
    std::fs::copy(binaries.join("pilot-fetch"), work.join("pilot-fetch"))?;
    for name in ["add", "multiply"] {
        let mut build = Command::new("rustc");
        build.args([
            "--edition",
            "2021",
            "-O",
            "--target",
            "x86_64-unknown-linux-musl",
        ]);
        if name == "add" {
            build.args(["--cfg", "add_tool"]);
        }
        ensure!(
            build
                .arg(root.join("crates/celln-pilot/tests/fixtures/arithmetic_tool.rs"))
                .arg("-o")
                .arg(work.join(name))
                .status()?
                .success(),
            "tool compile failed"
        );
    }
    std::fs::copy(work.join("add"), work.join("unselected"))?;
    let mut mk = Command::new(root.join("scripts/mktoolfs.sh"));
    mk.arg(work.join("toolfs.img")).arg("32");
    for name in ["harness", "pilot-fetch", "add", "multiply", "unselected"] {
        mk.arg(work.join(name));
    }
    ensure!(mk.status()?.success(), "toolfs build failed");
    let payload = std::fs::read(work.join("toolfs.img"))?;
    let mut members = BTreeMap::new();
    for name in ["harness", "pilot-fetch", "add", "multiply"] {
        members.insert(
            format!("/{name}"),
            Member {
                hash: Hash::of(&std::fs::read(work.join(name))?).0,
                dependencies: BTreeSet::new(),
            },
        );
    }
    members.get_mut("/harness").unwrap().dependencies = ["/pilot-fetch", "/add", "/multiply"]
        .into_iter()
        .map(String::from)
        .collect();
    let mut seed = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        toolfs: Hash::of(&payload).0,
        entrypoint: "/harness".into(),
        interpreter: false,
        members: members.clone(),
    }
    .sign(&seed)
    .map_err(anyhow::Error::msg)?;
    signed
        .verify(&BTreeSet::from([signed.publisher.clone()]))
        .map_err(anyhow::Error::msg)?;
    std::fs::write(
        work.join("signed-closure.json"),
        serde_json::to_vec_pretty(&signed)?,
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
            .env("CELLN_WARM_DISPATCH", "1")
            .env_remove("CELLN_RUN_JSON")
            .status()?
            .success(),
        "initrd build failed"
    );
    let kernel = BootConfig::host_kernel().context("no host kernel")?;
    let mut template = LinuxCell::boot(
        BootConfig::new(kernel)
            .with_pmem(payload.len())
            .with_initrd(work.join("initramfs.cpio")),
    )?;
    template.seal_tool(&Hash::of(&payload), &payload)?;
    template.stop_when_guest_prints("CELLN:mote=parked");
    ensure!(
        matches!(template.run()?.end, BootEnd::Parked),
        "template did not park"
    );
    let mote = template.park()?;
    let mut cell = LinuxCell::fork_from(&mote)?;
    cell.set_timeout(Duration::from_secs(180));
    let url = "https://api.deepseek.com/chat/completions";
    let mut policy = HttpPolicy::new(vec!["api.deepseek.com".into()]);
    policy.timeout = Duration::from_secs(45);
    policy.max_requests = 6;
    policy.json_posts.push(JsonPostGrant {
        url: url.into(),
        bearer_token_file: token,
        model: "deepseek-chat".into(),
        max_output_tokens: 512,
        max_total_output_tokens: 1536,
    });
    cell.enable_http_fetch(policy);
    let config = json!({"task":"Use add with args [\"37\",\"5\"], then use multiply with the returned result and \"2\". Wait for each tool result. Finally reply with exactly the final integer, no explanation.", "url":url,"model":"deepseek-chat","tools":[
        {"name":"add","path":"/add","hash":members["/add"].hash,"description":"Add two integer strings; returns their sum."},
        {"name":"multiply","path":"/multiply","hash":members["/multiply"].hash,"description":"Multiply two integer strings; returns their product."}
    ]});
    cell.set_invocation(&serde_json::to_vec(&json!({"path":"/harness","alias":"/harness","root":"/tools","args":[config.to_string()],"force_agent_lane":true,"agent_authored_input":true,"allow_fetch":true,"expected_hash":members["/harness"].hash,"workspace_access":"none","closure_members":members}))?)?;
    let report = cell.run()?;
    std::fs::write(work.join("console.log"), &report.console)?;
    let events: Vec<Value> = report
        .console
        .lines()
        .filter_map(|line| line.strip_prefix("CELLN_HARNESS_EVENT "))
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    std::fs::write(
        work.join("events.json"),
        serde_json::to_vec_pretty(&events)?,
    )?;
    ensure!(
        matches!(report.end, BootEnd::Shutdown),
        "cell did not shut down; evidence {}",
        work.display()
    );
    ensure!(
        report
            .console
            .contains("CELLN:pilot_run_/harness=permitted:agent"),
        "not agent lane"
    );
    ensure!(
        events.iter().any(|e| e["type"] == "negative-checks"
            && e["unselected"] == "EACCES"
            && e["toolWrites"] == "denied"),
        "negative probes failed; {}",
        work.display()
    );
    let calls: Vec<_> = events.iter().filter(|e| e["type"] == "tool").collect();
    ensure!(
        calls.len() == 2
            && calls[0]["name"] == "add"
            && calls[0]["args"] == json!(["37", "5"])
            && calls[0]["result"] == "42\n"
            && calls[1]["name"] == "multiply"
            && calls[1]["args"] == json!(["42", "2"])
            && calls[1]["result"] == "84\n",
        "incorrect tool sequence; {}",
        work.display()
    );
    ensure!(
        calls[0]["hash"] == members["/add"].hash && calls[1]["hash"] == members["/multiply"].hash,
        "tool identities differ"
    );
    ensure!(
        events.iter().filter(|e| e["type"] == "model").count() >= 3
            && events.iter().any(|e| e["type"] == "completed"
                && e["answer"].as_str().is_some_and(|s| s.trim() == "84")),
        "model did not consume results; {}",
        work.display()
    );
    for reason in [
        "model not granted",
        "model output token limit exceeded",
        "unsupported model request parameters",
        "model cumulative output budget exhausted",
    ] {
        ensure!(
            events
                .iter()
                .any(|e| e["type"] == "model-denied" && e["reason"] == reason),
            "missing guest model-policy denial: {reason}"
        );
    }
    ensure!(
        cell.fetch_activity().0 == 8 && cell.fetch_activity().1 == 5,
        "unexpected broker attempts or denials"
    );
    let evidence = json!({"scope":"direct-KVM reference Harness; not Sympozium dispatcher or Pi/Hermes","spawn":"warm mote CoW fork","publisher":signed.publisher,"toolfs":signed.closure.toolfs,"members":members,"fetchActivity":cell.fetch_activity(),"modelPolicy":{"model":"deepseek-chat","maxOutputTokens":512,"maxTotalOutputTokens":1536,"stream":false},"events":events});
    std::fs::write(
        work.join("evidence.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!("PASS: in-cell model loop used two lent tools, consumed results, answered 84; unselected exec denied. Evidence: {}",work.display());
    Ok(())
}
