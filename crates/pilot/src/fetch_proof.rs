//! Hardware proof for the pilot→warden HTTPS fetch capability.
//!
//! Run `cargo run -p pilot --features kvm --bin nous-fetch-proof -- URL` on a
//! KVM host. A pass means a program running *inside* a real cell invoked the
//! guest-only `/pilot-fetch` client and received a bounded HTTPS response from
//! the host broker. It is intentionally a host-authored probe, so no data-lane
//! exception is involved in proving the transport.

use anyhow::{bail, Context, Result};
use nous_manifest::{Author, Entry, Hash, Manifest, Tier};
use std::path::{Path, PathBuf};
use std::process::Command;
use warden::egress::HttpPolicy;
use warden::vmm::boot::{BootConfig, LinuxCell};

fn main() -> Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com/".into());
    let host = host_of(&url)?;
    let root = repo_root()?;
    let work = std::env::temp_dir().join(format!("nous-fetch-proof-{}", std::process::id()));
    std::fs::create_dir_all(&work)?;

    let probe = work.join("fetch-probe");
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
        .arg(root.join("examples/fetch_probe.rs"))
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
        author: Author::Host,
        recipe: None,
    });
    manifest.sign_standin();
    let manifest_path = work.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    let run_path = work.join("run.json");
    std::fs::write(
        &run_path,
        serde_json::to_vec(&serde_json::json!({
            "path": "/tools/fetch-probe", "alias": "/probe", "args": [url],
            "agent_authored_input": false,
        }))?,
    )?;

    let toolfs = work.join("toolfs.img");
    run(&root, "scripts/mktoolfs.sh", &[toolfs.as_path(), Path::new("32"), &probe])?;
    let initrd = work.join("initramfs.cpio");
    let mut init = Command::new(root.join("scripts/mkinitramfs.sh"));
    init.current_dir(&root)
        .arg(&initrd)
        .env("NOUS_MANIFEST", &manifest_path)
        .env("NOUS_RUN_JSON", &run_path);
    let out = init.output().context("building fetch-proof initramfs")?;
    if !out.status.success() {
        bail!("mkinitramfs: {}", String::from_utf8_lossy(&out.stderr).trim());
    }

    let kernel = BootConfig::host_kernel().context("no KVM-capable host kernel")?;
    let payload = std::fs::read(&toolfs)?;
    let mut cell = LinuxCell::boot(BootConfig::new(kernel).with_pmem(payload.len()).with_initrd(initrd))?;
    cell.enable_http_fetch(HttpPolicy::new(vec![host]));
    cell.seal_tool(&Hash::of(&payload), &payload)?;
    let report = cell.run()?;
    if !report.console.contains("NOUS_FETCH_OK bytes=") {
        bail!("guest fetch proof failed; console tail:\n{}", report.tail(40));
    }
    println!("PASS: a real cell fetched HTTPS through pilot; no guest network device was present");
    Ok(())
}

fn host_of(url: &str) -> Result<String> {
    let rest = url.strip_prefix("https://").context("proof URL must use https")?;
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
        .context("run from a nouscell checkout")
}

fn run(root: &Path, script: &str, args: &[&Path]) -> Result<()> {
    let status = Command::new(root.join(script)).current_dir(root).args(args).status()?;
    if status.success() { Ok(()) } else { bail!("{script} failed") }
}
