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
    ("/workspace-list", "celln-workspace-list"),
    ("/workspace-append", "celln-workspace-append"),
    ("/workspace-search", "celln-workspace-search"),
    ("/workspace-delete", "celln-workspace-delete"),
    ("/https-post-json", "celln-https-post-json"),
];

/// The brokered starter tools: each is its own bundle and every one is also a
/// member of the worker closure. Order is the bundle order in package.json.
pub(crate) const STARTER_TOOLS: [&str; 8] = [
    "workspace-read",
    "workspace-write",
    "https-fetch",
    "workspace-list",
    "workspace-append",
    "workspace-search",
    "workspace-delete",
    "https-post-json",
];

/// Worker tools beyond the brokered ones: the harness admits 24 per template.
pub(crate) const MAX_BORROWED_COMMANDS: usize = 24 - STARTER_TOOLS.len();

/// Where packaging subprocesses (mke2fs, debugfs, the initramfs script and
/// its compiler) are looked up: a fixed list, never the caller's PATH, and
/// including sbin because Debian keeps the e2fsprogs tools there.
const PACKAGING_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

pub(crate) fn regular(path: &Path, bound: usize) -> Result<Vec<u8>> {
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
    let result = command.env_clear().env("PATH", PACKAGING_PATH).output()?;
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

/// A command borrowed from a pinned image, as the package records it: the
/// alias its static executable is lent under, where it came from, and the
/// argv binding and parameters the configuring node turns into a tool.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PackagedCommand {
    pub alias: String,
    pub image: String,
    #[serde(rename = "sourceImage")]
    pub source_image: String,
    #[serde(flatten)]
    pub command: crate::tool_commands::CatalogueCommand,
}

/// Resolves `--tool-image` names against the catalogue in `root`, pulling
/// any image not yet materialised, and extracts each command's executable.
/// Only static Linux amd64 executables are lent: the worker closure lists
/// exact members and never consults a library directory inside the cell.
type Borrowed = (BTreeMap<String, Vec<u8>>, Vec<PackagedCommand>);

fn borrowed_commands(tool_images: &[String], root: &Path, o: &crate::out::Out) -> Result<Borrowed> {
    let mut programs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut commands = Vec::new();
    let mut names = BTreeSet::new();
    for name in tool_images {
        let (image, _) = crate::image::catalogue_entry_for(name, root)
            .or_else(|_| {
                crate::image::catalogue_in(root)
                    .images
                    .into_iter()
                    .find(|i| &i.name == name)
                    .map(|i| {
                        (
                            i,
                            crate::image::Provide {
                                alias: String::new(),
                                exec: String::new(),
                                interpreter: false,
                                language: None,
                                code_flag: None,
                            },
                        )
                    })
                    .context("no such catalogue image")
            })
            .with_context(|| format!("--tool-image {name}"))?;
        ensure!(
            !image.commands.is_empty(),
            "catalogue image {name} declares no commands to borrow"
        );
        if !crate::image::image_is_materialised(&image, root) {
            crate::image::pull(&image.ref_, root, o)?;
        }
        let ext2 = crate::image::materialised_path(&image, root);
        for command in &image.commands {
            crate::tool_commands::validate(command)?;
            ensure!(
                names.insert(command.name.clone()),
                "command {} is declared by more than one tool image",
                command.name
            );
            let alias = crate::tool_commands::alias_for(command);
            ensure!(
                !PROGRAMS.iter().any(|(a, _)| *a == alias),
                "command {} would shadow the starter program {alias}",
                command.name
            );
            let bytes = crate::image::extract(&ext2, &command.exec)
                .with_context(|| format!("{name}: {}", command.exec))?;
            static_executable(&bytes).with_context(|| format!("{name}: {}", command.exec))?;
            if let Some(existing) = programs.get(&alias) {
                ensure!(
                    existing == &bytes,
                    "two tool images lend different bytes as {alias}"
                );
            } else {
                programs.insert(alias.clone(), bytes);
            }
            commands.push(PackagedCommand {
                alias,
                image: image.name.clone(),
                source_image: image.ref_.clone(),
                command: command.clone(),
            });
        }
    }
    ensure!(
        commands.len() <= MAX_BORROWED_COMMANDS,
        "at most {MAX_BORROWED_COMMANDS} borrowed commands fit beside the {} starter tools",
        STARTER_TOOLS.len()
    );
    Ok((programs, commands))
}

/// A Linux amd64 ELF with no program interpreter: nothing outside the lent
/// bytes runs when it starts.
fn static_executable(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= 64
            && bytes.starts_with(b"\x7fELF\x02\x01")
            && bytes.get(18..20) == Some(&[62, 0]),
        "Linux amd64 ELF executable required"
    );
    let u16_at = |i: usize| u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
    let u32_at =
        |i: usize| u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap()) as usize;
    let (phoff, phentsize, phnum) = (u64_at(32), u16_at(54), u16_at(56));
    ensure!(
        phentsize == 56
            && phnum > 0
            && phoff
                .checked_add(phentsize * phnum)
                .is_some_and(|end| end <= bytes.len()),
        "malformed ELF program headers"
    );
    for i in 0..phnum {
        let kind = u32_at(phoff + i * phentsize);
        // PT_INTERP: a dynamic executable that needs a loader and libraries.
        ensure!(
            kind != 3,
            "dynamically linked; lend the whole image as a closure instead of a starter command"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    runtime: &Path,
    guest: &Path,
    kernel: &Path,
    key: &Path,
    output: &Path,
    tool_images: &[String],
    root: &Path,
    o: &crate::out::Out,
) -> Result<u8> {
    let (borrowed, commands) = borrowed_commands(tool_images, root, o)?;
    let report = prepare(runtime, guest, kernel, key, output, &borrowed, &commands)?;
    println!(
        "{}",
        json!({"packageHash":Hash::of(&regular(&output.join("package.json"), 65536)?), "package":report})
    );
    Ok(0)
}

pub(crate) fn prepare(
    runtime: &Path,
    guest: &Path,
    kernel: &Path,
    key: &Path,
    output: &Path,
    borrowed: &BTreeMap<String, Vec<u8>>,
    commands: &[PackagedCommand],
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
    for (alias, bytes) in borrowed {
        programs.insert(alias.as_str(), bytes.clone());
    }
    let starter_aliases: Vec<String> = STARTER_TOOLS
        .iter()
        .map(|name| format!("/{name}"))
        .collect();
    let mut worker_aliases = vec!["/worker", "/pilot-fetch"];
    worker_aliases.extend(starter_aliases.iter().map(String::as_str));
    for alias in borrowed.keys() {
        if !worker_aliases.contains(&alias.as_str()) {
            worker_aliases.push(alias.as_str());
        }
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
    let mut plan = vec![("parent", vec!["/parent"]), ("worker", worker_aliases)];
    for (name, alias) in STARTER_TOOLS.iter().zip(&starter_aliases) {
        plan.push((name, vec![alias.as_str(), "/pilot-fetch"]));
    }
    for (name, aliases) in plan {
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
    let mut report = json!({
        "apiVersion":"celln.native-starter-package/v1",
        "kernel":Hash::of(&kernel_bytes), "pilot":Hash::of(&pilot),
        "initSource":Hash::of(&init), "initramfsScript":Hash::of(&script),
        "programs":inputs, "bundles":bundles,
        // What this package's worker understands beyond the first contract.
        // `starter-configure` refuses a non-default
        // `modelConnection.maxOutputTokens` for a package that does not say
        // its worker reads `max_tokens` from the template.
        "harness":{"maxTokensConfigurable":true},
        "admitted":false, "executionAuthorized":false,
        "hardwareConformance":"not_checked", "readiness":"not_established"
    });
    if !commands.is_empty() {
        // Provenance and the model-facing binding of every borrowed command;
        // the configuring node turns these into template tools and catalogue
        // entries, and the same bytes are hashed under `programs`.
        report["commands"] = serde_json::to_value(commands)?;
    }
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
    let mut published: BTreeMap<&Hash, std::path::PathBuf> = BTreeMap::new();
    let hashes: BTreeMap<&str, Hash> = aliases
        .iter()
        .map(|a| (*a, Hash::of(&programs[a])))
        .collect();
    for alias in aliases {
        let bytes = &programs[alias];
        let path = rootfs.join(alias.trim_start_matches('/'));
        // The same bytes lent under several names (busybox applets) share
        // one file in the image.
        match published.get(&hashes[alias]) {
            Some(existing) => fs::hard_link(existing, &path)?,
            None => {
                publish(&path, bytes)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
                published.insert(&hashes[alias], path.clone());
            }
        }
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
    for name in STARTER_TOOLS {
        if let Some(member) = members.get_mut(&format!("/{name}")) {
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
        .env("PATH", PACKAGING_PATH)
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
    fn packages_ten_signed_bundles_without_admission() {
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
        let report = prepare(
            &repo,
            &guest,
            &kernel,
            &key,
            &output,
            &Default::default(),
            &[],
        )
        .unwrap();
        assert_eq!(report["admitted"], false);
        assert_eq!(report["executionAuthorized"], false);
        assert_eq!(report["harness"]["maxTokensConfigurable"], true);
        assert_eq!(report["bundles"].as_array().unwrap().len(), 10);
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
            for alias in STARTER_TOOLS.map(|name| format!("/{name}")) {
                if let Some(member) = signed.closure.members.get(&alias) {
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
        assert!(prepare(
            &repo,
            &guest,
            &kernel,
            &key,
            &output,
            &Default::default(),
            &[]
        )
        .is_err());
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
            &output,
            &Default::default(),
            &[]
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

#[cfg(test)]
mod static_tests {
    use super::*;

    fn elf(program_headers: &[u32]) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(&[62, 0]);
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&(program_headers.len() as u16).to_le_bytes());
        for kind in program_headers {
            let mut header = vec![0u8; 56];
            header[..4].copy_from_slice(&kind.to_le_bytes());
            bytes.extend(header);
        }
        bytes
    }

    // Only a static Linux amd64 executable is lent as a borrowed command: a
    // dynamic one would need a loader and libraries the closure never lists.
    #[test]
    fn only_static_amd64_executables_are_borrowed() {
        assert!(static_executable(&elf(&[1, 1])).is_ok(), "PT_LOAD only");
        assert!(static_executable(&elf(&[6, 3, 1])).is_err(), "PT_INTERP");
        assert!(static_executable(b"not an elf").is_err());
        let mut arm = elf(&[1]);
        arm[18] = 183;
        assert!(static_executable(&arm).is_err(), "wrong machine");
        let mut truncated = elf(&[1]);
        truncated[56] = 9;
        assert!(
            static_executable(&truncated).is_err(),
            "headers past the end"
        );
    }
}
