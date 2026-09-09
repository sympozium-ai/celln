//! Cold-path build packaging. No fixed test keys, trust-policy mutation, model
//! credentials, Kubernetes operations, VM boot or claims of hardware readiness.
use anyhow::{ensure, Context, Result};
use celln_manifest::{
    closure::{Closure, Member},
    Author, Hash,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
};

const PROGRAMS: &[(&str, &str)] = &[
    ("/parent", "celln-harness-parent"),
    ("/worker", "celln-harness-turn"),
    ("/pilot-fetch", "pilot-fetch"),
    ("/workspace-read", "celln-workspace-read"),
    ("/workspace-write", "celln-workspace-write"),
    ("/https-fetch", "celln-https-fetch"),
];

fn regular(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    ensure!(file.metadata()?.is_file(), "regular package input required");
    let mut bytes = Vec::new();
    file.take((bound + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= bound,
        "empty or oversized package input"
    );
    Ok(bytes)
}

fn publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn command(command: &mut Command) -> Result<()> {
    let result = command.env_clear().env("PATH", "/usr/bin:/bin").output()?;
    ensure!(
        result.status.success(),
        "package build subprocess failed (status {}); no completed package was published",
        result.status
    );
    Ok(())
}

// A pre-built ELF is an input, not proof of provenance or static compatibility.
// The operator reviews/signs these exact bytes; guest conformance is separate.
fn executable(path: &Path) -> Result<Vec<u8>> {
    let bytes = regular(path, 64 << 20)?;
    ensure!(
        bytes.starts_with(b"\x7fELF\x02\x01") && bytes.get(18..20) == Some(&[62, 0]),
        "Linux amd64 ELF input required: {}",
        path.display()
    );
    Ok(bytes)
}

pub fn run(runtime: &Path, guest: &Path, kernel: &Path, key: &Path, output: &Path) -> Result<u8> {
    let report = prepare(runtime, guest, kernel, key, output)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(0)
}

fn prepare(
    runtime: &Path,
    guest: &Path,
    kernel: &Path,
    key: &Path,
    output: &Path,
) -> Result<Value> {
    for path in [runtime, guest, kernel, key, output] {
        ensure!(
            path.is_absolute(),
            "explicit absolute packaging paths required"
        );
    }
    ensure!(!output.try_exists()?, "output must be a new directory");
    let kernel_bytes = regular(kernel, 64 << 20)?;
    let seed = zeroize::Zeroizing::new(regular(key, 32)?);
    ensure!(
        seed.len() == 32,
        "signing key must contain exactly 32 raw bytes"
    );
    let mut signing_seed = zeroize::Zeroizing::new([0u8; 32]);
    signing_seed.copy_from_slice(&seed);
    let mut programs = BTreeMap::new();
    for (alias, binary) in PROGRAMS {
        programs.insert(*alias, executable(&guest.join(binary))?);
    }
    let pilot = executable(&guest.join("celln-pilot"))?;
    let script = regular(&runtime.join("scripts/mkinitramfs.sh"), 1 << 20)?;
    let init = regular(&runtime.join("guest/init/init.c"), 1 << 20)?;
    // Validate all inputs before creating any output. Partial builds retain no
    // package.json completion marker; retry into a NEW directory, never replace.
    fs::DirBuilder::new().mode(0o700).create(output)?;
    let staging = tempfile::Builder::new()
        .prefix(".starter-build-")
        .tempdir_in(output)?;
    let runtime_copy = staging.path().join("runtime");
    for dir in ["scripts", "guest/init", "pilot"] {
        fs::create_dir_all(runtime_copy.join(dir))?;
    }
    publish(&runtime_copy.join("scripts/mkinitramfs.sh"), &script)?;
    publish(&runtime_copy.join("guest/init/init.c"), &init)?;
    for (name, bytes) in [
        ("celln-pilot", &pilot),
        ("pilot-fetch", &programs["/pilot-fetch"]),
    ] {
        let path = runtime_copy.join("pilot").join(name);
        publish(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    publish(&output.join("kernel"), &kernel_bytes)?;
    let mut bundles = Vec::new();
    for (name, aliases) in [
        ("parent", vec!["/parent"]),
        (
            "worker",
            vec![
                "/worker",
                "/pilot-fetch",
                "/workspace-read",
                "/workspace-write",
                "/https-fetch",
            ],
        ),
        ("workspace-read", vec!["/workspace-read", "/pilot-fetch"]),
        ("workspace-write", vec!["/workspace-write", "/pilot-fetch"]),
        ("https-fetch", vec!["/https-fetch", "/pilot-fetch"]),
    ] {
        bundles.push(bundle(
            output,
            staging.path(),
            &runtime_copy,
            name,
            &aliases,
            &programs,
            &kernel_bytes,
            &signing_seed,
        )?);
    }
    let inputs: BTreeMap<_, _> = programs
        .iter()
        .map(|(name, bytes)| (*name, Hash::of(bytes).0))
        .collect();
    let report = json!({
        "apiVersion":"celln.native-starter-package/v1",
        "kernel":Hash::of(&kernel_bytes), "pilot":Hash::of(&pilot),
        "initSource":Hash::of(&init), "initramfsScript":Hash::of(&script),
        "programs":inputs, "bundles":bundles,
        "admitted":false, "executionAuthorized":false,
        "hardwareConformance":"not_checked", "readiness":"not_established"
    });
    staging.close()?;
    publish(
        &output.join("package.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    fs::File::open(output)?.sync_all()?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
fn bundle(
    output: &Path,
    staging: &Path,
    runtime: &Path,
    name: &str,
    aliases: &[&str],
    programs: &BTreeMap<&str, Vec<u8>>,
    kernel: &[u8],
    key: &[u8; 32],
) -> Result<Value> {
    let build = staging.join(name);
    let rootfs = build.join("rootfs");
    fs::create_dir_all(rootfs.join("tmp"))?;
    // Explicit read/execute bits permit the capability-less guest to access
    // files regardless of the build user's uid retained by mke2fs -d.
    fs::set_permissions(&rootfs, fs::Permissions::from_mode(0o755))?;
    let mut members = BTreeMap::new();
    for alias in aliases {
        let bytes = &programs[alias];
        let path = rootfs.join(alias.trim_start_matches('/'));
        publish(&path, bytes)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))?;
        members.insert(
            (*alias).to_owned(),
            Member {
                hash: Hash::of(bytes).0,
                dependencies: BTreeSet::new(),
            },
        );
    }
    members.get_mut(aliases[0]).unwrap().dependencies =
        aliases.iter().skip(1).map(|s| (*s).to_owned()).collect();
    // Each starter executable invokes pilot-fetch; record that edge even when
    // all tools are also transitive dependencies of the worker entrypoint.
    for alias in ["/workspace-read", "/workspace-write", "/https-fetch"] {
        if let Some(member) = members.get_mut(alias) {
            member.dependencies.insert("/pilot-fetch".to_owned());
        }
    }
    let image_path = build.join("toolfs.ext2");
    command(
        Command::new("mke2fs")
            .args(["-q", "-t", "ext2", "-b", "4096", "-F", "-d"])
            .arg(&rootfs)
            .arg(&image_path)
            .arg("8192"),
    )?;
    let image = regular(&image_path, 64 << 20)?;
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        sources: vec![],
        toolfs: Hash::of(&image).0,
        entrypoint: aliases[0].into(),
        interpreter: false,
        members,
    }
    .sign(key)
    .map_err(anyhow::Error::msg)?;
    let signed_bytes = serde_json::to_vec(&signed)?;
    let assay_root = build.join("assay");
    assay::Assayer::open(&assay_root)?.admit_verified_authored(
        aliases[0],
        &programs[aliases[0]],
        false,
        Author::Host,
    )?;
    let initrd_path = build.join("initrd");
    // No user startup files or inherited model credentials reach the build.
    // The copied script/source and supplied pilot bytes are the recorded inputs.
    let result = Command::new("/bin/bash")
        .arg(runtime.join("scripts/mkinitramfs.sh"))
        .arg(&initrd_path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("CELLN_MANIFEST", assay_root.join("manifest.json"))
        .env("CELLN_PILOT_DIR", runtime.join("pilot"))
        .output()?;
    ensure!(
        result.status.success(),
        "initramfs packaging failed; no completion marker published"
    );
    let initrd = regular(&initrd_path, 64 << 20)?;
    ensure!(
        initrd.starts_with(b"070701"),
        "uncompressed newc initrd required"
    );
    let executable = Hash::of(&programs[aliases[0]]);
    let mote = serde_json::to_vec(
        &json!({"apiVersion":"celln.dev/v1alpha1","format":"celln.warm-closure-v1","kernel":Hash::of(kernel),"initrd":Hash::of(&initrd),"toolfs":Hash::of(&image),"invocation":{"alias":aliases[0],"toolHash":executable}}),
    )?;
    let directory = output.join(name);
    fs::create_dir(&directory)?;
    for (file, bytes) in [
        ("signed-closure.json", signed_bytes.as_slice()),
        ("mote.json", mote.as_slice()),
        ("initrd", initrd.as_slice()),
        ("toolfs.ext2", image.as_slice()),
        ("executable", programs[aliases[0]].as_slice()),
    ] {
        publish(&directory.join(file), bytes)?;
    }
    fs::File::open(&directory)?.sync_all()?;
    Ok(
        json!({"name":name,"publisher":signed.publisher,"entryPoint":aliases[0],"executable":executable,"closure":Hash::of(&signed_bytes),"mote":Hash::of(&mote),"initrd":Hash::of(&initrd),"toolfs":Hash::of(&image)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "explicit cold packaging test: requires kernel, guest binaries, gcc/cpio/mke2fs; no KVM or model"]
    fn packages_five_signed_bundles_without_admission() {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let guest = repo.join("target/x86_64-unknown-linux-musl/release");
        let kernel =
            warden::vmm::boot::BootConfig::host_kernel().expect("readable kernel required");
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        fs::write(&key, [17u8; 32]).unwrap();
        let output = dir.path().join("package");
        let report = prepare(&repo, &guest, &kernel, &key, &output).unwrap();
        assert_eq!(report["admitted"], false);
        assert_eq!(report["executionAuthorized"], false);
        assert_eq!(report["bundles"].as_array().unwrap().len(), 5);
        for entry in report["bundles"].as_array().unwrap() {
            let bundle = output.join(entry["name"].as_str().unwrap());
            let raw = fs::read(bundle.join("signed-closure.json")).unwrap();
            let signed: celln_manifest::closure::SignedClosure =
                serde_json::from_slice(&raw).unwrap();
            let expected = signed.closure.clone().sign(&[17u8; 32]).unwrap().publisher;
            signed.verify(&BTreeSet::from([expected.clone()])).unwrap();
            assert_eq!(entry["publisher"], expected);
            for (file, field) in [
                ("signed-closure.json", "closure"),
                ("mote.json", "mote"),
                ("initrd", "initrd"),
                ("toolfs.ext2", "toolfs"),
                ("executable", "executable"),
            ] {
                assert_eq!(
                    entry[field],
                    Hash::of(&fs::read(bundle.join(file)).unwrap()).0
                );
            }
            for alias in ["/workspace-read", "/workspace-write", "/https-fetch"] {
                if let Some(member) = signed.closure.members.get(alias) {
                    assert!(member.dependencies.contains("/pilot-fetch"));
                    assert!(signed.closure.members.contains_key("/pilot-fetch"));
                }
            }
            let mut tampered = signed.clone();
            tampered.closure.toolfs = Hash::of(b"changed").0;
            assert!(tampered.verify(&BTreeSet::from([expected])).is_err());
        }
        assert!(!output.join("trusted-motes.json").exists());
        assert!(!output.join("trusted-closures.json").exists());
        assert!(!output.join("key").exists());
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(prepare(&repo, &guest, &kernel, &key, &output).is_err());
    }

    #[test]
    fn refuses_invalid_inputs_without_publication() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("package");
        assert!(prepare(
            Path::new("relative"),
            dir.path(),
            dir.path(),
            dir.path(),
            &output
        )
        .is_err());
        assert!(!output.exists());
        let input = dir.path().join("input");
        fs::write(&input, b"not an ELF").unwrap();
        assert!(executable(&input).is_err());
        assert!(regular(&input, 2).is_err());
        let symlink = dir.path().join("alias");
        std::os::unix::fs::symlink(&input, &symlink).unwrap();
        assert!(regular(&symlink, 100).is_err());
        assert!(regular(dir.path(), 100).is_err());
        publish(&output, b"original").unwrap();
        assert!(publish(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original");
    }
}
