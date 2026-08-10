//! OCI images as sealed tool filesystems.
//!
//! A tool that is a dependency closure — a binary, its loader, and the shared
//! objects it resolves by absolute path — cannot be lent as a single file. An
//! OCI image already is that closure, so it is pulled by digest, flattened to
//! a rootfs, built into a deterministic ext2 image, and admitted to the store.
//! Sealing happens later, at cell construction, against bytes that already
//! exist: materialising here would put a network pull on the spawn path.

use crate::out::{bold, dim, green, Out};
use anyhow::{bail, Context, Result};
use celln_manifest::Hash;
use std::path::{Path, PathBuf};
use std::process::Command;

/// nd_pmem refuses a namespace whose length is not 2 MiB aligned.
const PMEM_ALIGN: u64 = 2 << 20;
/// ext2 block size; the block count must be a multiple of `PMEM_ALIGN`.
const BLOCK: u64 = 4096;
/// Headroom over the rootfs for inodes and metadata.
const OVERHEAD_NUM: u64 = 6;
const OVERHEAD_DEN: u64 = 5;

/// Fixed identity so the same rootfs always yields the same bytes, and
/// therefore the same hash and one shared physical copy across cells.
const IMAGE_UUID: &str = "ce11ce11-0000-4000-8000-000000000001";

pub fn images_dir(root: &Path) -> PathBuf {
    root.join("images")
}

fn require(tool: &str) -> Result<()> {
    if crate::agent::which(tool).is_none() {
        bail!("`{tool}` is not on PATH; it is needed to pull OCI images");
    }
    Ok(())
}

/// Reject anything that is not an immutable reference. A tag can be moved, and
/// a moved tag would silently change what a cell is lent.
fn digest_of(reference: &str) -> Result<String> {
    let r = reference.trim_start_matches("docker://");
    let Some((_, digest)) = r.split_once('@') else {
        bail!(
            "{reference} is not digest-pinned. Use name@sha256:<64 hex> — a tag \
             is mutable and cannot carry tool-lane authority.\n  \
             resolve it with: skopeo inspect --format '{{{{.Digest}}}}' docker://{r}"
        );
    };
    let Some(hex) = digest.strip_prefix("sha256:") else {
        bail!("{reference}: only sha256 digests are supported");
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{reference}: sha256 digest must be 64 hex characters");
    }
    Ok(digest.to_owned())
}

fn sh(program: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!(
            "{program} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Layers apply in manifest order; that ordering is the image.
fn layer_digests(dir: &Path) -> Result<Vec<String>> {
    let manifest = std::fs::read(dir.join("manifest.json")).context("reading image manifest")?;
    let v: serde_json::Value = serde_json::from_slice(&manifest)?;
    let layers = v
        .get("layers")
        .and_then(serde_json::Value::as_array)
        .context("image manifest has no layers")?;
    layers
        .iter()
        .map(|l| {
            l.get("digest")
                .and_then(serde_json::Value::as_str)
                .map(|d| d.trim_start_matches("sha256:").to_owned())
                .context("layer without a digest")
        })
        .collect()
}

fn dir_bytes(path: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(e.path());
            } else {
                total += md.len();
            }
        }
    }
    total
}

fn build_ext2(rootfs: &Path, out: &Path) -> Result<()> {
    let want = dir_bytes(rootfs) * OVERHEAD_NUM / OVERHEAD_DEN + (16 << 20);
    let blocks_per_align = PMEM_ALIGN / BLOCK;
    let blocks = want.div_ceil(BLOCK).div_ceil(blocks_per_align) * blocks_per_align;

    let _ = std::fs::remove_file(out);
    let status = Command::new("mke2fs")
        .args(["-q", "-t", "ext2", "-b", "4096", "-d"])
        .arg(rootfs)
        .args(["-F", "-U", IMAGE_UUID, "-E"])
        .arg(format!("root_owner=0:0,hash_seed={IMAGE_UUID}"))
        .arg(out)
        .arg(blocks.to_string())
        .env("SOURCE_DATE_EPOCH", "0")
        .status()
        .context("running mke2fs (install e2fsprogs)")?;
    if !status.success() {
        bail!("mke2fs failed building the tool filesystem");
    }
    Ok(())
}

/// Read one file out of a built image without mounting it.
///
/// Pilot re-hashes the bytes it finds at this path inside the cell, so the
/// manifest has to carry that file's hash, not the whole image's.
pub fn extract(image: &Path, inside: &str) -> Result<Vec<u8>> {
    let work = tempfile::tempdir()?;
    let out = work.path().join("f");
    let status = Command::new("debugfs")
        .arg("-R")
        .arg(format!("dump {inside} {}", out.display()))
        .arg(image)
        .output()
        .context("running debugfs (install e2fsprogs)")?;
    let bytes = std::fs::read(&out).map_err(|_| {
        anyhow::anyhow!(
            "{inside} is not in the image: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        )
    })?;
    if bytes.is_empty() {
        bail!("{inside} is empty in the image");
    }
    Ok(bytes)
}

/// Pull `reference`, flatten it, and admit the resulting filesystem image.
pub fn pull(reference: &str, root: &Path, o: &Out) -> Result<u8> {
    require("skopeo")?;
    let digest = digest_of(reference)?;
    let name = reference.trim_start_matches("docker://");

    let dir = images_dir(root);
    std::fs::create_dir_all(&dir)?;
    let image_path = dir.join(format!("{}.ext2", digest.replace(':', "_")));
    if image_path.exists() {
        let bytes = std::fs::read(&image_path)?;
        o.event(
            "image_present",
            serde_json::json!({
                "reference": name, "digest": digest,
                "path": image_path.display().to_string(), "bytes": bytes.len(),
                "hash": Hash::of(&bytes).0,
            }),
            format!("  {} already materialised  {}", dim("≡"), dim(&digest)),
        );
        return Ok(crate::exit::OK);
    }

    let work = tempfile::tempdir()?;
    let blobs = work.path().join("blobs");
    o.event(
        "image_pull",
        serde_json::json!({ "reference": name, "digest": digest }),
        format!("{} pulling {}", bold("●"), dim(&digest)),
    );
    sh(
        "skopeo",
        &[
            "copy",
            "--quiet",
            &format!("docker://{name}"),
            &format!("dir:{}", blobs.display()),
        ],
    )?;

    let rootfs = work.path().join("rootfs");
    std::fs::create_dir_all(&rootfs)?;
    let layers = layer_digests(&blobs)?;
    for layer in &layers {
        // Ownership is recorded by the archive, not by the extracting user.
        sh(
            "tar",
            &[
                "-xf",
                &blobs.join(layer).display().to_string(),
                "-C",
                &rootfs.display().to_string(),
                "--no-same-owner",
            ],
        )
        .with_context(|| format!("extracting layer {layer}"))?;
    }
    o.note(format!(
        "  {} {} layer(s), {} MiB",
        dim("·"),
        layers.len(),
        dir_bytes(&rootfs) / (1 << 20)
    ));

    build_ext2(&rootfs, &image_path)?;
    let bytes = std::fs::read(&image_path)?;
    let hash = Hash::of(&bytes);
    let mut assayer = assay::Assayer::open(root).context("opening the tool store")?;
    assayer
        .admit_verified(&format!("/image/{digest}"), &bytes, false)
        .context("admitting the image")?;

    o.event(
        "image_ready",
        serde_json::json!({
            "reference": name, "digest": digest, "hash": hash.0,
            "bytes": bytes.len(), "path": image_path.display().to_string(),
            "tier": "verified",
        }),
        format!(
            "  {} {} MiB  tier=verified  {}",
            green("+"),
            bytes.len() / (1 << 20),
            dim(&hash.0)
        ),
    );
    Ok(crate::exit::OK)
}

pub fn list(root: &Path, o: &Out) -> Result<u8> {
    let dir = images_dir(root);
    let mut rows: Vec<(String, u64)> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "ext2"))
        .filter_map(|e| {
            let len = e.metadata().ok()?.len();
            let name = e.path().file_stem()?.to_string_lossy().replace('_', ":");
            Some((name, len))
        })
        .collect();
    rows.sort();
    if rows.is_empty() {
        o.note(dim("no images — `celln image pull <name@sha256:...>`"));
        return Ok(crate::exit::OK);
    }
    for (digest, len) in rows {
        o.event(
            "image",
            serde_json::json!({ "digest": digest, "bytes": len }),
            format!("  {:<78} {:>5} MiB", digest, len / (1 << 20)),
        );
    }
    Ok(crate::exit::OK)
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    #[test]
    fn a_tag_is_refused_and_a_digest_is_accepted() {
        assert!(digest_of("docker://python:3.12-slim").is_err());
        assert!(digest_of("python").is_err());
        let ok = format!("docker://python@sha256:{}", "a".repeat(64));
        assert_eq!(
            digest_of(&ok).unwrap(),
            format!("sha256:{}", "a".repeat(64))
        );
    }

    #[test]
    fn a_malformed_digest_is_refused() {
        assert!(digest_of("python@sha256:short").is_err());
        assert!(digest_of(&format!("python@sha256:{}", "z".repeat(64))).is_err());
        assert!(digest_of(&format!("python@sha512:{}", "a".repeat(64))).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use celln_manifest::Hash;
    use std::path::{Path, PathBuf};

    /// Stage the guest assets the initramfs script needs, mirroring
    /// `dispatch::tests::test_runtime_root`.
    fn runtime_root(work: &Path) -> Option<PathBuf> {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root");
        let pilot_dir = repo.join("target/x86_64-unknown-linux-musl/release");
        if !pilot_dir.join("celln-pilot").exists() {
            eprintln!("skipping: build celln-pilot for x86_64-unknown-linux-musl first");
            return None;
        }
        let root = work.join("runtime");
        std::fs::create_dir_all(root.join("scripts")).unwrap();
        std::fs::create_dir_all(root.join("pilot")).unwrap();
        std::fs::create_dir_all(root.join("guest/init")).unwrap();
        for s in ["mktoolfs.sh", "mkinitramfs.sh"] {
            std::fs::copy(repo.join("scripts").join(s), root.join("scripts").join(s)).unwrap();
        }
        std::fs::copy(
            repo.join("guest/init/init.c"),
            root.join("guest/init/init.c"),
        )
        .unwrap();
        for b in ["celln-pilot", "pilot-fetch"] {
            std::fs::copy(pilot_dir.join(b), root.join("pilot").join(b)).unwrap();
        }
        Some(root)
    }

    /// Boot a cell from a prepared image and run one program in it.
    ///
    /// `revoke_on`, when set, makes the host delete the sealed memslot the
    /// moment the guest prints that marker — which is how the VFS↔memslot join
    /// is proven behaviourally rather than assumed.
    fn run_in_sealed_image(
        args: &[String],
        revoke_on: Option<&str>,
    ) -> Option<(warden::vmm::boot::BootReport, String)> {
        use warden::vmm::boot::{BootConfig, LinuxCell};

        if !Path::new("/dev/kvm").exists() {
            eprintln!("skipping: no /dev/kvm");
            return None;
        }
        let (Ok(image_path), Ok(rootfs), Ok(exec)) = (
            std::env::var("CELLN_IMAGE_TEST_IMAGE"),
            std::env::var("CELLN_IMAGE_TEST_ROOTFS"),
            std::env::var("CELLN_IMAGE_TEST_EXEC"),
        ) else {
            eprintln!("skipping: set CELLN_IMAGE_TEST_IMAGE / _ROOTFS / _EXEC");
            return None;
        };

        let work = tempfile::tempdir().expect("work dir");
        let runtime = runtime_root(work.path())?;

        let image = std::fs::read(&image_path).expect("read sealed image");
        eprintln!("image: {} bytes", image.len());

        // Exec-by-hash still governs: hash the exact binary inside the image
        // that pilot will be asked to run, and admit that hash. The rest of the
        // image is present but nothing else is what pilot was asked to exec.
        let on_host = PathBuf::from(&rootfs).join(exec.trim_start_matches('/'));
        let program = std::fs::read(&on_host).expect("read program from rootfs");
        let store = work.path().join("store");
        std::fs::create_dir_all(&store).unwrap();
        let mut assayer = assay::Assayer::open(&store).expect("open store");
        let alias = format!("/image{exec}");
        let admitted = assayer
            .admit_verified(&alias, &program, false)
            .expect("admit program");
        assert_eq!(admitted, Hash::of(&program));

        // The request pilot reads in-cell. `root` is the new part: enter the
        // sealed image as / before exec, so the loader finds its own libs.
        let run_json = work.path().join("run.json");
        std::fs::write(
            &run_json,
            serde_json::to_vec_pretty(&serde_json::json!({
                "path": exec,
                "alias": alias,
                "args": args,
                "agent_authored_input": false,
                "root": "/tools",
            }))
            .unwrap(),
        )
        .unwrap();

        let initrd = work.path().join("initramfs.cpio");
        crate::agent::sh_env(
            &runtime,
            "scripts/mkinitramfs.sh",
            &[initrd.display().to_string()],
            &[
                (
                    "CELLN_MANIFEST",
                    store.join("manifest.json").display().to_string(),
                ),
                ("CELLN_RUN_JSON", run_json.display().to_string()),
                (
                    "CELLN_PILOT_DIR",
                    runtime.join("pilot").display().to_string(),
                ),
            ],
        )
        .expect("build initramfs");

        let kernel = BootConfig::host_kernel().expect("host kernel with matching modules");
        let mut cfg = BootConfig::new(&kernel)
            .with_pmem(image.len())
            .with_initrd(&initrd);
        if let Ok(mb) = std::env::var("CELLN_IMAGE_TEST_MEM_MB") {
            cfg.mem_size = mb.parse::<usize>().expect("mem mb") << 20;
        }
        let image_hash = Hash::of(&image);
        let mut cell = LinuxCell::boot(cfg).expect("boot cell");
        cell.seal_tool(&image_hash, &image).expect("seal the image");
        if let Some(marker) = revoke_on {
            cell.revoke_when_guest_prints(&image_hash, marker);
        }
        let r = cell.run().expect("run cell");
        eprintln!("---- guest console ----\n{}\n----", r.console);
        Some((r, alias))
    }

    #[test]
    #[ignore = "needs /dev/kvm and a prepared image; run explicitly"]
    fn a_dynamically_linked_tool_runs_from_a_sealed_oci_image() {
        let args: Vec<String> = std::env::var("CELLN_IMAGE_TEST_ARGS")
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        let Some((r, alias)) = run_in_sealed_image(&args, None) else {
            return;
        };

        assert_eq!(
            r.guest_report("dax_mount"),
            Some("ok"),
            "the sealed image must mount over DAX"
        );
        // The read-only remount used to be skipped for any real image, because
        // it sat behind an early return taken when `/tools/probe` (a test
        // fixture no real image carries) could not be opened. A read-write
        // mount over a read-only memslot makes writes report success and land
        // nowhere, and eventually kills the guest in writeback. Assert it here
        // so that regression cannot come back quietly.
        assert_eq!(
            r.guest_report("dax_ro_mount"),
            Some("ok"),
            "a sealed image must end up mounted read-only, whatever it contains"
        );
        assert_eq!(
            r.guest_report(&format!("pilot_run_{alias}"))
                .map(|v| v.to_string()),
            Some("permitted:tool".to_string()),
            "exec-by-hash must permit the admitted binary"
        );
        let out = crate::agent::slice_output(&r.console);
        assert!(
            out.is_some(),
            "a dynamically linked binary must actually run out of the sealed image"
        );
        eprintln!("PROGRAM OUTPUT: {:?}", out);
    }

    /// The VFS↔memslot join, proven for a *real image* rather than the probe
    /// fixture.
    ///
    /// Execution working does not prove the join. If the guest were reading a
    /// page-cache copy of the image rather than the sealed memslot itself,
    /// everything would still run — but each cell would hold its own copy
    /// (destroying the one-physical-copy sharing story) and revocation could
    /// never reach a running cell.
    ///
    /// So: read a file, print a marker, and let the host delete the memslot at
    /// that exact point. If the mapping is genuinely the sealed pages, the read
    /// *after* revocation cannot still return the original bytes.
    #[test]
    #[ignore = "needs /dev/kvm and a prepared image; run explicitly"]
    fn revocation_reaches_a_cell_running_out_of_a_sealed_image() {
        const MARKER: &str = "CELLN-REVOKE-NOW";
        let probe = std::env::var("CELLN_IMAGE_TEST_PROBE_FILE")
            .unwrap_or_else(|_| "/etc/alpine-release".to_string());
        let script = format!(
            "echo BEFORE=$(cat {probe}); echo {MARKER}; sleep 1; \
             echo AFTER=$(cat {probe} 2>&1); echo DONE"
        );
        let args = vec!["sh".to_string(), "-c".to_string(), script];

        let Some((r, _alias)) = run_in_sealed_image(&args, Some(MARKER)) else {
            return;
        };
        let out = crate::agent::slice_output(&r.console).unwrap_or_default();
        eprintln!("PROGRAM OUTPUT:\n{out}");

        let before = out
            .lines()
            .find_map(|l| l.strip_prefix("BEFORE="))
            .map(str::trim)
            .unwrap_or("");
        let after = out
            .lines()
            .find_map(|l| l.strip_prefix("AFTER="))
            .map(str::trim)
            .unwrap_or("");
        assert!(
            !before.is_empty(),
            "the guest must be able to read the sealed image before revocation"
        );

        // The observed mechanism is stronger than "the second read differs":
        // the process is *executing* out of the sealed pages — its own dynamic
        // loader's text lives there — so deleting the memslot kills it mid-run
        // with an invalid-opcode trap inside ld-musl. Asserting only that the
        // reads differ would pass trivially on an empty string, so assert that
        // the program could not run to completion.
        assert!(
            !out.contains("DONE"),
            "the program ran to completion after its sealed pages were revoked \
             — it is holding a page-cache copy, not the sealed memslot, so the \
             VFS↔memslot join is NOT closed for this image"
        );
        assert_ne!(
            before, after,
            "the same file read identically after revocation — page-cache copy"
        );
        eprintln!("join proven: revocation stopped a running dynamically linked program");
    }
}
