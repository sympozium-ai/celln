//! Spike: seal an OCI image as the tool lane and run a dynamically linked
//! program out of it, inside a real cell.
//!
//! This exists to answer one question that could not be settled by reading:
//! **can a cell run a tool that is a dependency closure rather than a single
//! static binary?** Every tool the cell has ever run has been a static musl
//! binary celln itself built. A real tool — python, curl, node — is a binary
//! plus a loader plus a tree of shared objects, resolved by absolute path.
//!
//! The approach: an OCI image already *is* that closure, content-addressed and
//! built by an ecosystem that solved the packaging problem. Extract it to a
//! rootfs, build a deterministic ext2 image, seal that as the pmem tool window,
//! and have pilot `chroot` into it before exec so `/lib/ld-musl-x86_64.so.1`
//! resolves against the image instead of against a host that isn't there.
//!
//! Nothing here is a product surface yet. It is deliberately driven by
//! environment variables pointing at a prepared image, so the expensive part
//! (pulling and converting an image) stays outside the test.

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

    /// Seal a prepared OCI-derived ext2 image and run a dynamically linked
    /// binary out of it in a real cell.
    ///
    /// Driven by two env vars so the image build stays out of the test:
    ///   CELLN_SPIKE_IMAGE  — the ext2 image built from an image rootfs
    ///   CELLN_SPIKE_ROOTFS — that same rootfs on the host, to hash the binary
    ///   CELLN_SPIKE_EXEC   — path *inside* the image, e.g. /bin/busybox
    ///   CELLN_SPIKE_ARGS   — newline-separated args
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
            std::env::var("CELLN_SPIKE_IMAGE"),
            std::env::var("CELLN_SPIKE_ROOTFS"),
            std::env::var("CELLN_SPIKE_EXEC"),
        ) else {
            eprintln!("skipping: set CELLN_SPIKE_IMAGE / _ROOTFS / _EXEC");
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
        // RAM must clear the tool window, which sits as a hole in low memory.
        // A full image needs a wider window, and therefore a bigger cell —
        // precisely the coupling the writeup argues should be removed.
        if let Ok(mb) = std::env::var("CELLN_SPIKE_MEM_MB") {
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
    #[ignore = "needs /dev/kvm and a prepared OCI image; run explicitly"]
    fn a_dynamically_linked_tool_runs_from_a_sealed_oci_image() {
        let args: Vec<String> = std::env::var("CELLN_SPIKE_ARGS")
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        let Some((r, alias)) = run_in_sealed_image(&args, None) else {
            return;
        };

        // NOTE: this asserts `dax_mount`, not `dax_ro_mount`, and that is a
        // finding rather than a preference. init.c only performs the
        // read-only remount *after* successfully opening `/tools/probe` — a
        // test fixture no real image contains — so with a genuine OCI image
        // it returns early and the tool mount stays read-write. The hardware
        // seal still refuses the writes, but the guest holds a read-write
        // superblock, which is exactly the dirty-page/writeback situation
        // init.c's own comments say production wants to avoid.
        assert_eq!(
            r.guest_report("dax_mount"),
            Some("ok"),
            "the sealed image must mount over DAX"
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
    #[ignore = "needs /dev/kvm and a prepared OCI image; run explicitly"]
    fn revocation_reaches_a_cell_running_out_of_a_sealed_image() {
        const MARKER: &str = "CELLN-REVOKE-NOW";
        let probe = std::env::var("CELLN_SPIKE_PROBE_FILE")
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
