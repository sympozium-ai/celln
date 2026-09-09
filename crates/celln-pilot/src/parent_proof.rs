//! Explicit real-KVM proof; local test signing identity, not production admission.
use anyhow::{ensure, Context, Result};
use celln_manifest::{
    closure::{Closure, Member},
    Author, Entry, Hash, Manifest, Tier,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::Command,
};
use warden::vmm::boot::{BootConfig, BootEnd, LinuxCell};

#[path = "proof_credential.rs"]
mod credential;
#[path = "parent_turn_proof.rs"]
mod turns;

fn main() -> Result<()> {
    let real = std::env::args().any(|arg| arg == "--real-model");
    let borrowed = std::env::args().any(|arg| arg == "--borrowed-tool");
    let cancel_child = std::env::args().any(|arg| arg == "--cancel-child");
    ensure!(
        !cancel_child || !real,
        "cancellation proof is deterministic only"
    );
    ensure!(
        !borrowed || real,
        "borrowed-tool proof requires --real-model"
    );
    let args: Vec<String> = std::env::args().collect();
    let local_key = if let Some(index) = args.iter().position(|arg| arg == "--key-from-zshrc") {
        ensure!(real, "startup key reading requires explicit --real-model");
        Some(credential::from_zshrc(std::path::Path::new(
            args.get(index + 1).context("missing startup file path")?,
        ))?)
    } else {
        None
    };
    let native = real || cancel_child || std::env::args().any(|arg| arg == "--native-turns");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binaries = PathBuf::from(
        std::env::var_os("CELLN_PILOT_DIR").context("static Pilot directory required")?,
    );
    let work = root.join(format!(
        "target/parent-confined-proof-{}",
        std::process::id()
    ));
    std::fs::create_dir(&work)?;
    if native {
        std::fs::copy(binaries.join("celln-harness-parent"), work.join("parent"))?;
    } else {
        ensure!(
            Command::new("rustc")
                .args([
                    "--edition=2021",
                    "-O",
                    "--target",
                    "x86_64-unknown-linux-musl"
                ])
                .arg(root.join("crates/celln-pilot/tests/fixtures/parent_confined.rs"))
                .arg("-o")
                .arg(work.join("parent"))
                .status()?
                .success(),
            "fixture compilation failed"
        );
    }
    let mut mk = Command::new(root.join("scripts/mktoolfs.sh"));
    mk.arg(work.join("toolfs.img"))
        .arg("32")
        .arg(work.join("parent"));
    let worker_hash = if native {
        if real {
            std::fs::copy(binaries.join("celln-harness-turn"), work.join("worker"))?;
            std::fs::copy(binaries.join("pilot-fetch"), work.join("pilot-fetch"))?;
            mk.arg(work.join("pilot-fetch"));
            if borrowed {
                ensure!(
                    Command::new("rustc")
                        .args([
                            "--edition=2021",
                            "-O",
                            "--target",
                            "x86_64-unknown-linux-musl",
                            "--cfg",
                            "uppercase_tool"
                        ])
                        .arg(root.join("crates/celln-pilot/tests/fixtures/json_tool.rs"))
                        .arg("-o")
                        .arg(work.join("uppercase"))
                        .status()?
                        .success(),
                    "borrowed tool build failed"
                );
                mk.arg(work.join("uppercase"));
            }
        } else {
            ensure!(
                Command::new("rustc")
                    .args([
                        "--edition=2021",
                        "-O",
                        "--target",
                        "x86_64-unknown-linux-musl"
                    ])
                    .arg(root.join("crates/celln-pilot/tests/fixtures/turn_echo.rs"))
                    .arg("-o")
                    .arg(work.join("worker"))
                    .status()?
                    .success(),
                "worker build failed"
            );
        }
        mk.arg(work.join("worker"));
        Some(Hash::of(&std::fs::read(work.join("worker"))?))
    } else {
        None
    };
    ensure!(mk.status()?.success(), "toolfs failed");
    let payload = std::fs::read(work.join("toolfs.img"))?;
    let hash = Hash::of(&std::fs::read(work.join("parent"))?);
    let members = BTreeMap::from([(
        "/parent".to_string(),
        Member {
            hash: hash.0.clone(),
            dependencies: BTreeSet::new(),
        },
    )]);
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        sources: vec![],
        toolfs: Hash::of(&payload).0,
        entrypoint: "/parent".into(),
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
    if let Some(worker) = &worker_hash {
        let mut worker_members = BTreeMap::from([(
            "/worker".into(),
            Member {
                hash: worker.0.clone(),
                dependencies: BTreeSet::new(),
            },
        )]);
        if real {
            worker_members
                .get_mut("/worker")
                .unwrap()
                .dependencies
                .insert("/pilot-fetch".into());
            worker_members.insert(
                "/pilot-fetch".into(),
                Member {
                    hash: Hash::of(&std::fs::read(work.join("pilot-fetch"))?).0,
                    dependencies: BTreeSet::new(),
                },
            );
            if borrowed {
                worker_members
                    .get_mut("/worker")
                    .unwrap()
                    .dependencies
                    .insert("/uppercase".into());
                worker_members.insert(
                    "/uppercase".into(),
                    Member {
                        hash: Hash::of(&std::fs::read(work.join("uppercase"))?).0,
                        dependencies: BTreeSet::new(),
                    },
                );
            }
        }
        let worker_signed = Closure {
            api_version: "celln.dev/closure-v1".into(),
            sources: vec![],
            toolfs: Hash::of(&payload).0,
            entrypoint: "/worker".into(),
            interpreter: false,
            members: worker_members,
        }
        .sign(&[42; 32])
        .map_err(anyhow::Error::msg)?;
        worker_signed
            .verify(&BTreeSet::from([worker_signed.publisher.clone()]))
            .map_err(anyhow::Error::msg)?;
        std::fs::write(
            work.join("worker-closure.json"),
            serde_json::to_vec(&worker_signed)?,
        )?;
        manifest.admit(Entry {
            alias: "/worker".into(),
            hash: worker.clone(),
            tier: Tier::Verified,
            interpreter: false,
            author: Author::Host,
            recipe: None,
        });
    }
    manifest.admit(Entry {
        alias: "/parent".into(),
        hash: hash.clone(),
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
        "initrd failed"
    );
    let mut template = LinuxCell::boot(
        BootConfig::new(BootConfig::host_kernel().context("kernel required")?)
            .with_pmem(payload.len())
            .with_initrd(work.join("initramfs.cpio")),
    )?;
    template.seal_tool(&Hash::of(&payload), &payload)?;
    template.stop_when_guest_prints("CELLN:mote=parked");
    ensure!(
        template.run()?.end == BootEnd::Parked,
        "template did not park"
    );
    let mote = template.park()?;
    drop(template);
    let mut parent = LinuxCell::fork_from(&mote)?;
    let invocation = serde_json::json!({
        "path":"/parent", "alias":"/parent", "root":"/tools", "args":[],
        "force_agent_lane":true, "agent_authored_input":true, "allow_parent_mailbox":true,
        "expected_hash":hash.0, "workspace_access":"none", "report_output_limit":8192,
        "closure_members":members
    });
    parent.set_invocation(&serde_json::to_vec(&invocation)?)?;
    parent.enable_parent_mailbox()?;
    if let Some(worker_hash) = worker_hash {
        let token = if real {
            Some(if let Some(key) = &local_key {
                key.path.clone()
            } else {
                PathBuf::from(
                    std::env::var_os("CELLN_MODEL_TOKEN_FILE")
                        .context("real model requires explicit host credential file")?,
                )
            })
        } else {
            None
        };
        return turns::run(
            parent,
            mote,
            worker_hash,
            work,
            token,
            borrowed,
            cancel_child,
        );
    }
    for (turn, message) in [
        (1, &b"remember:private"[..]),
        (2, &b"recall"[..]),
        (3, &b"recall"[..]),
    ] {
        parent.deliver_parent_message(message)?;
        let report = parent.run()?;
        ensure!(
            report.end == BootEnd::Parked,
            "parent failed: {}",
            report.tail(30)
        );
        ensure!(
            parent.take_parent_response()?.context("no response")?
                == format!("confined:{turn}:private").as_bytes(),
            "guest state mismatch"
        );
        ensure!(
            !report.console.contains("Linux version"),
            "parent booted on hot path"
        );
    }
    let mut ungranted = LinuxCell::fork_from(&mote)?;
    let mut without_grant = invocation;
    without_grant["allow_parent_mailbox"] = serde_json::json!(false);
    ungranted.set_invocation(&serde_json::to_vec(&without_grant)?)?;
    ungranted.enable_parent_mailbox()?;
    ungranted.deliver_parent_message(b"recall")?;
    let report = ungranted.run()?;
    ensure!(
        report.end == BootEnd::Shutdown,
        "ungranted guest did not terminate: {}",
        report.tail(30)
    );
    ensure!(
        ungranted.take_parent_response()?.is_none(),
        "ungranted guest accessed mailbox"
    );
    // Require the actual failed port instruction's guest signal, not merely
    // a timeout or a guest that failed for an unrelated packaging reason.
    ensure!(
        report.console.contains("\"signal\":11"),
        "missing guest SIGSEGV for ungranted I/O: {}",
        report.tail(30)
    );
    println!("PASS: sealed parent through Pilot, 3 retained-state turns, guest capabilities empty; forbidden ioperm/iopl/network/device creation/raw-device access/code write refused; ungranted guest I/O faults. Evidence: {}", work.display());
    Ok(())
}
