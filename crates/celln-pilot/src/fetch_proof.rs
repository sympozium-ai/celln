//! Hardware proof for the pilot→warden HTTPS fetch capability.
//!
//! Run `cargo run -p celln-pilot --features kvm --bin celln-fetch-proof -- URL` on a
//! KVM host. A pass means a program running *inside* a real cell invoked the
//! guest-only `/pilot-fetch` client, proved that pilot's three-port broker works
//! while the adjacent port is denied, and received a bounded HTTPS response
//! from the host broker. It deliberately runs in the agent lane, which is the public
//! `celln agent --allow-host` path and the one that must be able to execute the
//! broker client without receiving authority over other guest code.

use anyhow::{bail, Context, Result};
use celln_manifest::{Author, Entry, Hash, Manifest, Tier};
use std::path::{Path, PathBuf};
use std::process::Command;
use warden::egress::{HttpPolicy, JsonPostGrant};
use warden::vmm::boot::{BootConfig, LinuxCell};

fn main() -> Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com/".into());
    let host = host_of(&url)?;
    let model_token_file = std::env::var_os("CELLN_MODEL_TOKEN_FILE").map(PathBuf::from);
    let request = if model_token_file.is_some() {
        serde_json::json!({
            "apiVersion":"celln.fetch/v1", "method":"POST", "url":url,
            "body": {"model":"deepseek-chat", "max_tokens":64, "stream":false,
                "messages":[{"role":"user","content":"Reply with exactly CELLN_MODEL_PROOF_OK and no other text."}]}
        }).to_string()
    } else {
        url.clone()
    };
    let root = repo_root()?;
    let work = std::env::temp_dir().join(format!("celln-fetch-proof-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;

    let probe = work.join("program");
    let compiled = Command::new("rustc")
        .current_dir(&root)
        .args([
            "--edition",
            "2021",
            "-O",
            "--target",
            "x86_64-unknown-linux-musl",
            "-C",
            "target-feature=+crt-static",
            "-o",
        ])
        .arg(&probe)
        .arg(root.join("crates/celln-pilot/tests/fixtures/fetch_probe.rs"))
        .status()
        .context("building guest fetch probe")?;
    if !compiled.success() {
        bail!("guest fetch probe did not compile")
    }

    let bytes = std::fs::read(&probe)?;
    let hash = Hash::of(&bytes);
    let mut manifest = Manifest::new();
    manifest.admit(Entry {
        alias: "/probe".into(),
        hash,
        tier: Tier::Verified,
        interpreter: false,
        author: Author::Agent,
        recipe: None,
    });
    manifest.sign_standin();
    let manifest_path = work.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let run_path = work.join("run.json");
    std::fs::write(
        &run_path,
        serde_json::to_vec(&serde_json::json!({
            "path": "/tools/program", "alias": "/probe", "args": [request, if model_token_file.is_some() { "model" } else { "get" }],
            "agent_authored_input": true,
            "allow_fetch": true,
        }))?,
    )?;

    let toolfs = work.join("toolfs.img");
    run(
        &root,
        "scripts/mktoolfs.sh",
        &[toolfs.as_path(), Path::new("32"), &probe],
    )?;
    let initrd = work.join("initramfs.cpio");
    let mut init = Command::new(root.join("scripts/mkinitramfs.sh"));
    init.current_dir(&root)
        .arg(&initrd)
        .env("CELLN_MANIFEST", &manifest_path)
        .env("CELLN_RUN_JSON", &run_path);
    let out = init.output().context("building fetch-proof initramfs")?;
    if !out.status.success() {
        bail!(
            "mkinitramfs: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    let kernel = BootConfig::host_kernel().context("no KVM-capable host kernel")?;
    let payload = std::fs::read(&toolfs)?;
    let mut cell = LinuxCell::boot(
        BootConfig::new(kernel)
            .with_pmem(payload.len())
            .with_initrd(initrd),
    )?;
    let mut policy = HttpPolicy::new(vec![host]);
    if let Some(bearer_token_file) = model_token_file {
        policy.json_posts.push(JsonPostGrant {
            url,
            bearer_token_file,
        });
        policy.timeout = std::time::Duration::from_secs(45);
        cell.set_timeout(std::time::Duration::from_secs(90));
    }
    cell.enable_http_fetch(policy);
    cell.seal_tool(&Hash::of(&payload), &payload)?;
    let report = cell.run()?;
    if !report
        .console
        .contains("CELLN:pilot_run_/probe=permitted:agent")
        || !report
            .console
            .contains("CELLN_SECCOMP_BYPASSES_DENIED io_uring=EPERM x32_socket=EPERM")
        || !report
            .console
            .contains("CELLN_FETCH_IOPERM_OK ports=0x500-0x502 denied=0x503:SIGSEGV")
        || !report
            .console
            .contains("CELLN_FETCH_CAPABILITY_SCOPE_OK widen=EPERM iopl=EPERM")
        || !report
            .console
            .contains("CELLN_FETCH_RAW_DEVICES_OK inaccessible")
        || !report.console.contains("CELLN_FETCH_OK bytes=")
    {
        bail!(
            "guest fetch proof failed; console tail:\n{}",
            report.tail(40)
        );
    }
    println!(
        "PASS: a real cell used only broker ports 0x500-0x502 and fetched HTTPS through pilot"
    );
    for line in report
        .console
        .lines()
        .filter(|line| line.contains("CELLN_MODEL_RESPONSE"))
    {
        println!("{line}");
    }
    println!("host-observed fetch counters: {:?}", cell.fetch_activity());
    Ok(())
}

fn host_of(url: &str) -> Result<String> {
    let rest = url
        .strip_prefix("https://")
        .context("proof URL must use https")?;
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() || host.contains(':') || host.contains('@') {
        bail!("proof URL must have a plain DNS host on port 443")
    }
    Ok(host.to_owned())
}

fn repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    cwd.ancestors()
        .find(|p| p.join("scripts/mkinitramfs.sh").exists())
        .map(Path::to_path_buf)
        .context("run from a Celln checkout")
}

fn run(root: &Path, script: &str, args: &[&Path]) -> Result<()> {
    let status = Command::new(root.join(script))
        .current_dir(root)
        .args(args)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        bail!("{script} failed")
    }
}
