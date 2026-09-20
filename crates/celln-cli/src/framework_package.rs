//! Operator-only native package construction for the scoped framework path.
//! This creates artifacts and public trust inputs, but never installs them,
//! contacts a cluster/model/provider, or mints request authority.
use anyhow::{ensure, Context, Result};
use celln_manifest::{
    closure::{composition, Closure, Member, SignedClosure},
    Author, Entry, Hash, Manifest, Tier,
};
use celln_store::Store;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const IMAGE_BYTES: u64 = 32 * 1024 * 1024;
const INPUT_SCHEMA: &str = r#"{"type":"object","properties":{"text":{"type":"string","minLength":1,"maxLength":256}},"required":["text"],"additionalProperties":false}"#;
const OUTPUT_SCHEMA: &str = INPUT_SCHEMA;

struct Keys {
    runtime: Zeroizing<[u8; 32]>,
    tool: Zeroizing<[u8; 32]>,
    parent: Zeroizing<[u8; 32]>,
    composer: Zeroizing<[u8; 32]>,
}

struct Built {
    signed: SignedClosure,
    descriptor: Vec<u8>,
    image: Vec<u8>,
}

struct Bundle {
    name: &'static str,
    entrypoint: &'static str,
    executable: Hash,
    closure: Hash,
    mote: Hash,
    initrd: Hash,
    toolfs: Hash,
    publisher: String,
    source_closure: Hash,
}

pub fn run(
    runtime: &Path,
    guest: &Path,
    kernel: &Path,
    source_revision: &str,
    source_tree_sha256: &str,
    source_epoch: u64,
    output: &Path,
) -> Result<u8> {
    let report = prepare(
        runtime,
        guest,
        kernel,
        source_revision,
        source_tree_sha256,
        source_epoch,
        output,
    )?;
    let package = read_regular(&output.join("package.json"), 1 << 20)?;
    println!(
        "{}",
        json!({"package":output,"packageHash":Hash::of(&package),"artifacts":report["artifacts"],"resources":report["resources"]})
    );
    Ok(0)
}

pub fn inspect(package: &Path) -> Result<u8> {
    ensure!(package.is_absolute(), "absolute package path required");
    let package_bytes = read_regular(&package.join("package.json"), 1 << 20)?;
    let metadata: Value = serde_json::from_slice(&package_bytes)?;
    ensure!(
        metadata["apiVersion"] == "celln.framework-native-package/v1",
        "unsupported framework package"
    );
    let manifest = String::from_utf8(read_regular(&package.join("MANIFEST.blake3"), 4 << 20)?)?;
    let mut paths = BTreeSet::new();
    for line in manifest.lines() {
        let (hex, relative) = line
            .split_once("  ")
            .context("invalid package manifest line")?;
        ensure!(
            hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid package manifest hash"
        );
        let relative = Path::new(relative);
        ensure!(
            !relative.is_absolute()
                && relative
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)))
                && paths.insert(relative.to_owned()),
            "invalid or duplicate package manifest path"
        );
        ensure!(
            Hash::of(&fs::read(package.join(relative))?).0 == format!("blake3:{hex}"),
            "package manifest identity mismatch: {}",
            relative.display()
        );
    }
    fn collect(directory: &Path, root: &Path, actual: &mut BTreeSet<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                collect(&path, root, actual)?;
            } else if path != root.join("MANIFEST.blake3") {
                actual.insert(path.strip_prefix(root)?.to_owned());
            }
        }
        Ok(())
    }
    let mut actual = BTreeSet::new();
    collect(package, package, &mut actual)?;
    ensure!(
        actual == paths,
        "package manifest does not cover exact file set"
    );
    let policy: Value = serde_json::from_slice(&read_regular(
        &package.join("authority/trusted-closures.json"),
        65536,
    )?)?;
    ensure!(
        policy["apiVersion"] == "celln.dev/closure-policy-v1"
            && policy["revoked"].as_array().is_some_and(Vec::is_empty),
        "invalid package closure policy"
    );
    let publishers = policy["publishers"]
        .as_array()
        .context("missing package publishers")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("invalid publisher")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let closures = Store::open(package.join("authority/closures"))?;
    let tools = Store::open(package.join("authority/tools"))?;
    let motes = Store::open(package.join("authority/motes"))?;
    let schemas = Store::open(package.join("authority/tool-schemas"))?;
    let artifacts = metadata["artifacts"]
        .as_array()
        .context("missing package artifacts")?;
    ensure!(artifacts.len() == 3, "expected three native artifacts");
    let mut mote_ids = BTreeSet::new();
    for artifact in artifacts {
        let name = artifact["name"].as_str().context("invalid artifact name")?;
        ensure!(
            matches!(name, "one-shot" | "enduring-worker" | "parent"),
            "unexpected artifact"
        );
        let directory = package.join("artifacts").join(name);
        let descriptor = read_regular(&directory.join("signed-closure.json"), 262144)?;
        let signed: SignedClosure = serde_json::from_slice(&descriptor)?;
        signed.verify(&publishers).map_err(anyhow::Error::msg)?;
        let closure_hash = Hash::of(&descriptor);
        ensure!(
            artifact["closure"] == closure_hash.0
                && closures.get_bounded(&closure_hash, 262144)? == descriptor,
            "closure store mismatch"
        );
        let image = read_regular(&directory.join("toolfs.ext2"), IMAGE_BYTES as usize)?;
        ensure!(
            signed.closure.toolfs == Hash::of(&image).0
                && artifact["toolfs"] == signed.closure.toolfs,
            "closure final image mismatch"
        );
        let entrypoint = artifact["entryPoint"]
            .as_str()
            .context("missing artifact entrypoint")?;
        let executable = read_regular(&directory.join("executable"), 64 << 20)?;
        let executable_hash = Hash::of(&executable);
        ensure!(
            signed.closure.entrypoint == entrypoint
                && signed.closure.members[entrypoint].hash == executable_hash.0
                && artifact["executable"] == executable_hash.0
                && tools.get_bounded(&executable_hash, 64 << 20)? == executable,
            "artifact executable mismatch"
        );
        let initrd = read_regular(&directory.join("initrd"), 64 << 20)?;
        let mote_bytes = read_regular(&directory.join("mote.json"), 16384)?;
        let mote: Value = serde_json::from_slice(&mote_bytes)?;
        let mote_hash = Hash::of(&mote_bytes);
        ensure!(
            artifact["mote"] == mote_hash.0
                && artifact["initrd"] == Hash::of(&initrd).0
                && mote["toolfs"] == signed.closure.toolfs
                && mote["initrd"] == Hash::of(&initrd).0
                && mote["invocation"]["alias"] == entrypoint
                && mote["invocation"]["toolHash"] == executable_hash.0
                && motes.get_bounded(&mote_hash, 16384)? == mote_bytes,
            "mote bundle mismatch"
        );
        mote_ids.insert(mote_hash.0);
    }
    let mote_policy: Value = serde_json::from_slice(&read_regular(
        &package.join("authority/trusted-motes.json"),
        65536,
    )?)?;
    ensure!(
        mote_policy["apiVersion"] == "celln.dev/v1alpha1"
            && mote_policy["bundles"]
                .as_array()
                .is_some_and(|values| values
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<BTreeSet<_>>()
                    == mote_ids.iter().map(String::as_str).collect()),
        "trusted mote policy mismatch"
    );
    for field in ["arguments", "result"] {
        let hash = Hash(
            metadata["schemas"][field]
                .as_str()
                .context("missing schema identity")?
                .into(),
        );
        let bytes = schemas.get_bounded(&hash, 32768)?;
        celln_manifest::tool_schema::ToolSchema::parse(&bytes, &hash)
            .map_err(anyhow::Error::msg)?;
    }
    for hash in metadata["sources"]
        .as_object()
        .context("missing source identities")?
        .values()
    {
        closures.get_bounded(
            &Hash(hash.as_str().context("invalid source identity")?.into()),
            262144,
        )?;
    }
    println!(
        "{}",
        json!({"apiVersion":"celln.framework-native-package-verification/v1","package":package,
            "packageHash":Hash::of(&package_bytes),"files":paths.len(),"closures":6,"artifacts":3,
            "schemas":2,"privateSigningMaterial":false,"executionAuthorized":false,"hardwareConformance":"not_checked"})
    );
    Ok(0)
}

fn prepare(
    runtime: &Path,
    guest: &Path,
    kernel: &Path,
    source_revision: &str,
    source_tree_sha256: &str,
    source_epoch: u64,
    output: &Path,
) -> Result<Value> {
    for path in [runtime, guest, kernel, output] {
        ensure!(path.is_absolute(), "absolute packaging paths required");
    }
    ensure!(!output.try_exists()?, "output must be a new directory");
    ensure!(
        (7..=64).contains(&source_revision.len())
            && source_revision.bytes().all(|b| b.is_ascii_hexdigit()),
        "source revision must be 7..64 hexadecimal characters"
    );
    ensure!(
        source_tree_sha256
            .strip_prefix("sha256:")
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
            }),
        "source tree SHA-256 must use sha256:<64 hex>"
    );
    ensure!(
        (946684800..=4102444800).contains(&source_epoch),
        "source epoch must be a bounded Unix timestamp"
    );
    let kernel_bytes = read_regular(kernel, 64 << 20)?;
    let pilot = executable(&guest.join("celln-pilot"))?;
    let pilot_fetch = executable(&guest.join("pilot-fetch"))?;
    let one_shot = executable(&guest.join("celln-harness-json"))?;
    let worker = executable(&guest.join("celln-harness-turn"))?;
    let parent = executable(&guest.join("celln-harness-parent"))?;
    let uppercase = executable(&guest.join("celln-uppercase"))?;
    for path in [
        runtime.join("scripts/mkinitramfs.sh"),
        runtime.join("guest/init/init.c"),
    ] {
        read_regular(&path, 1 << 20)?;
    }
    let keys = Keys {
        runtime: random_seed()?,
        tool: random_seed()?,
        parent: random_seed()?,
        composer: random_seed()?,
    };

    fs::DirBuilder::new().mode(0o755).create(output)?;
    let staging = tempfile::Builder::new()
        .prefix(".framework-package-")
        .tempdir_in(output)?;
    let sources_dir = output.join("sources");
    let artifacts_dir = output.join("artifacts");
    fs::create_dir(&sources_dir)?;
    fs::create_dir(&artifacts_dir)?;

    let runtime_members = BTreeMap::from([
        ("/harness", one_shot.as_slice()),
        ("/pilot-fetch", pilot_fetch.as_slice()),
    ]);
    let worker_members = BTreeMap::from([
        ("/worker", worker.as_slice()),
        ("/pilot-fetch", pilot_fetch.as_slice()),
    ]);
    let tool_members = BTreeMap::from([("/uppercase", uppercase.as_slice())]);
    let parent_members = BTreeMap::from([("/parent", parent.as_slice())]);
    let runtime_source = source(
        staging.path(),
        &sources_dir,
        "one-shot-runtime",
        "/harness",
        &runtime_members,
        &["/pilot-fetch"],
        &keys.runtime,
        source_epoch,
    )?;
    let worker_source = source(
        staging.path(),
        &sources_dir,
        "enduring-worker",
        "/worker",
        &worker_members,
        &["/pilot-fetch"],
        &keys.runtime,
        source_epoch,
    )?;
    let tool_source = source(
        staging.path(),
        &sources_dir,
        "uppercase-tool",
        "/uppercase",
        &tool_members,
        &[],
        &keys.tool,
        source_epoch,
    )?;
    let parent_source = source(
        staging.path(),
        &sources_dir,
        "parent",
        "/parent",
        &parent_members,
        &[],
        &keys.parent,
        source_epoch,
    )?;
    let one_composed = composed(
        staging.path(),
        &artifacts_dir,
        "one-shot",
        &[&runtime_source, &tool_source],
        &runtime_members,
        &tool_members,
        &keys.composer,
        source_epoch,
    )?;
    let worker_composed = composed(
        staging.path(),
        &artifacts_dir,
        "enduring-worker",
        &[&worker_source, &tool_source],
        &worker_members,
        &tool_members,
        &keys.composer,
        source_epoch,
    )?;
    write_built(&artifacts_dir.join("parent"), &parent_source)?;

    let authority = output.join("authority");
    fs::create_dir(&authority)?;
    let tools = Store::open(authority.join("tools"))?;
    let closures = Store::open(authority.join("closures"))?;
    let motes = Store::open(authority.join("motes"))?;
    let schemas = Store::open(authority.join("tool-schemas"))?;
    for bytes in [&one_shot, &worker, &parent, &uppercase, &pilot_fetch] {
        tools.put(bytes)?;
    }
    for built in [
        &runtime_source,
        &worker_source,
        &tool_source,
        &parent_source,
        &one_composed,
        &worker_composed,
    ] {
        ensure!(closures.put(&built.descriptor)? == Hash::of(&built.descriptor));
    }
    let input_schema = schemas.put(INPUT_SCHEMA.as_bytes())?;
    let output_schema = schemas.put(OUTPUT_SCHEMA.as_bytes())?;

    let runtime_copy = staging.path().join("runtime");
    copy_runtime(runtime, &runtime_copy, &pilot, &pilot_fetch)?;
    let one_initrd = initrd(
        &runtime_copy,
        staging.path(),
        "one-shot",
        "/harness",
        &one_shot,
        source_epoch,
    )?;
    let worker_initrd = initrd(
        &runtime_copy,
        staging.path(),
        "enduring-worker",
        "/worker",
        &worker,
        source_epoch,
    )?;
    let parent_initrd = initrd(
        &runtime_copy,
        staging.path(),
        "parent",
        "/parent",
        &parent,
        source_epoch,
    )?;
    let bundles = [
        bundle(
            "one-shot",
            "/harness",
            &one_shot,
            &one_composed,
            &runtime_source,
            &one_initrd,
            &kernel_bytes,
            &artifacts_dir,
            &motes,
        )?,
        bundle(
            "enduring-worker",
            "/worker",
            &worker,
            &worker_composed,
            &worker_source,
            &worker_initrd,
            &kernel_bytes,
            &artifacts_dir,
            &motes,
        )?,
        bundle(
            "parent",
            "/parent",
            &parent,
            &parent_source,
            &parent_source,
            &parent_initrd,
            &kernel_bytes,
            &artifacts_dir,
            &motes,
        )?,
    ];

    let publishers = BTreeSet::from([
        runtime_source.signed.publisher.clone(),
        tool_source.signed.publisher.clone(),
        parent_source.signed.publisher.clone(),
        one_composed.signed.publisher.clone(),
    ]);
    publish_json(
        &authority.join("trusted-closures.json"),
        &json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":publishers,"revoked":[]}),
    )?;
    publish_json(
        &authority.join("trusted-motes.json"),
        &json!({"apiVersion":"celln.dev/v1alpha1","bundles":bundles.iter().map(|b| b.mote.0.clone()).collect::<Vec<_>>() }),
    )?;

    let revision = format!(
        "r-{}-{}",
        source_revision[..12.min(source_revision.len())].to_ascii_lowercase(),
        &Hash::of(&one_shot).0[7..19]
    );
    let resources = resources(
        &revision,
        &bundles,
        &runtime_source,
        &worker_source,
        &tool_source,
        &input_schema,
        &output_schema,
        source_revision,
        source_tree_sha256,
    );
    publish(&output.join("resources.yaml"), resources.as_bytes(), 0o644)?;
    let parent_metadata = json!({
        "apiVersion":"celln.native-scoped-parent-artifact/v1",
        "source":{"revision":source_revision,"treeSHA256":source_tree_sha256,"epoch":source_epoch},
        "artifact":{"executable":{"hash":bundles[2].executable},"closure":{"hash":bundles[2].closure},"mote":{"hash":bundles[2].mote},
            "sourceClosure":{"hash":bundles[2].source_closure},"publisherKey":bundles[2].publisher,"entryPoint":"/parent","platform":"linux/amd64","lane":"agent"},
        "limits":{"memoryBytes":134217728,"workspace":"none","egress":[]},
        "operatorMetadataOnly":true,"runAuthority":false
    });
    publish_json(&output.join("parent-request.json"), &parent_metadata)?;

    let bundle_values = bundles
        .iter()
        .map(|b| json!({"name":b.name,"entryPoint":b.entrypoint,"executable":b.executable,"closure":b.closure,"mote":b.mote,
            "initrd":b.initrd,"toolfs":b.toolfs,"publisherKey":b.publisher,"sourceClosure":b.source_closure}))
        .collect::<Vec<_>>();
    let report = json!({
        "apiVersion":"celln.framework-native-package/v1",
        "source":{"repository":"https://github.com/sympozium-ai/celln","revision":source_revision,"treeSHA256":source_tree_sha256,"epoch":source_epoch,
            "cargoLock":Hash::of(&read_regular(&runtime.join("Cargo.lock"),8<<20)?),
            "initSource":Hash::of(&read_regular(&runtime.join("guest/init/init.c"),1<<20)?),
            "initramfsScript":Hash::of(&read_regular(&runtime.join("scripts/mkinitramfs.sh"),1<<20)?)},
        "inputs":{"kernel":Hash::of(&kernel_bytes),"pilot":Hash::of(&pilot),"pilotFetch":Hash::of(&pilot_fetch),
            "oneShot":Hash::of(&one_shot),"worker":Hash::of(&worker),"parent":Hash::of(&parent),"uppercase":Hash::of(&uppercase)},
        "schemas":{"arguments":input_schema,"result":output_schema,"profile":"celln.tool-schema/v1","maxBlobBytes":32768},
        "artifacts":bundle_values,
        "sources":{"oneShotRuntime":Hash::of(&runtime_source.descriptor),"enduringRuntime":Hash::of(&worker_source.descriptor),
            "uppercaseTool":Hash::of(&tool_source.descriptor),"parent":Hash::of(&parent_source.descriptor)},
        "publishers":publishers,
        "resources":{"file":"resources.yaml","profiles":[{"name":"celln-json-one-shot","revision":revision},{"name":"celln-json-enduring","revision":revision}],
            "tools":[{"name":"uppercase","revision":revision}],"parentRequest":"parent-request.json"},
        "contracts":{"direct":"celln.json-direct/v1","model":"celln.json-tools/v1","tool":"celln.json-stdio/v1"},
        "privateSigningMaterialExported":false,"credentialsIncluded":false,"executionAuthorized":false,
        "hardwareConformance":"not_checked","readiness":"not_established"
    });
    staging.close()?;
    publish_json(&output.join("package.json"), &report)?;
    write_manifest(output)?;
    normalize_modes(output)?;
    fs::File::open(output)?.sync_all()?;
    Ok(report)
}

fn random_seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/dev/urandom")?
        .read_exact(seed.as_mut())?;
    Ok(seed)
}

fn read_regular(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    ensure!(file.metadata()?.is_file(), "regular input required");
    let mut bytes = Vec::new();
    file.take((bound + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= bound,
        "empty or oversized input"
    );
    Ok(bytes)
}

fn executable(path: &Path) -> Result<Vec<u8>> {
    let bytes = read_regular(path, 64 << 20)?;
    ensure!(
        bytes.starts_with(b"\x7fELF\x02\x01") && bytes.get(18..20) == Some(&[62, 0]),
        "Linux amd64 ELF required: {}",
        path.display()
    );
    Ok(bytes)
}

fn publish(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn publish_json(path: &Path, value: &Value) -> Result<()> {
    publish(path, &serde_json::to_vec_pretty(value)?, 0o644)
}

fn set_time(path: &Path, epoch: u64) -> Result<()> {
    let time = UNIX_EPOCH + Duration::from_secs(epoch);
    fs::File::open(path)?.set_times(fs::FileTimes::new().set_accessed(time).set_modified(time))?;
    Ok(())
}

fn image(
    staging: &Path,
    name: &str,
    members: &BTreeMap<&str, &[u8]>,
    epoch: u64,
) -> Result<Vec<u8>> {
    let root = staging.join(format!("{name}-root"));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    let tmp = root.join("tmp");
    fs::create_dir(&tmp)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o1777))?;
    for (alias, bytes) in members {
        let path = root.join(alias.trim_start_matches('/'));
        fs::create_dir_all(path.parent().unwrap())?;
        publish(&path, bytes, 0o555)?;
        set_time(&path, epoch)?;
    }
    set_time(&tmp, epoch)?;
    set_time(&root, epoch)?;
    let image = staging.join(format!("{name}.ext2"));
    let mut identity = Vec::new();
    identity.extend_from_slice(name.as_bytes());
    for (path, bytes) in members {
        identity.extend_from_slice(path.as_bytes());
        identity.extend_from_slice(Hash::of(bytes).0.as_bytes());
    }
    let hex = &Hash::of(&identity).0[7..39];
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    let result = Command::new("/usr/sbin/mke2fs")
        .args(["-q", "-t", "ext2", "-b", "4096", "-m", "0", "-F", "-U"])
        .arg(&uuid)
        .arg("-E")
        .arg(format!(
            "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed={uuid}"
        ))
        .arg("-d")
        .arg(&root)
        .arg(&image)
        .arg((IMAGE_BYTES / 4096).to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("E2FSPROGS_FAKE_TIME", epoch.to_string())
        .output()?;
    ensure!(result.status.success(), "ext2 materialization failed");
    // mke2fs -d otherwise imports the staging inode ctime, which callers
    // cannot set through the filesystem API. Normalize it inside the image;
    // debugfs updates metadata checksums and honors the same fake clock.
    let commands = staging.join(format!("{name}-debugfs.commands"));
    let mut normalization =
        format!("set_inode_field / ctime @{epoch}\nset_inode_field /tmp ctime @{epoch}\n");
    for alias in members.keys() {
        normalization.push_str(&format!("set_inode_field {alias} ctime @{epoch}\n"));
    }
    publish(&commands, normalization.as_bytes(), 0o600)?;
    let result = Command::new("/usr/sbin/debugfs")
        .args(["-w", "-f"])
        .arg(&commands)
        .arg(&image)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("E2FSPROGS_FAKE_TIME", epoch.to_string())
        .output()?;
    ensure!(
        result.status.success(),
        "ext2 timestamp normalization failed"
    );
    let bytes = read_regular(&image, IMAGE_BYTES as usize)?;
    ensure!(
        bytes.len() == IMAGE_BYTES as usize,
        "unexpected ext2 image size"
    );
    fs::remove_dir_all(root)?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn source(
    staging: &Path,
    output: &Path,
    name: &str,
    entrypoint: &str,
    files: &BTreeMap<&str, &[u8]>,
    dependencies: &[&str],
    key: &[u8; 32],
    epoch: u64,
) -> Result<Built> {
    let image = image(staging, &format!("source-{name}"), files, epoch)?;
    let mut members = files
        .iter()
        .map(|(path, bytes)| {
            (
                (*path).to_owned(),
                Member {
                    hash: Hash::of(bytes).0,
                    dependencies: BTreeSet::new(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    members.get_mut(entrypoint).unwrap().dependencies =
        dependencies.iter().map(|s| (*s).to_owned()).collect();
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        toolfs: Hash::of(&image).0,
        entrypoint: entrypoint.into(),
        interpreter: false,
        members,
        sources: vec![],
    }
    .sign(key)
    .map_err(anyhow::Error::msg)?;
    let descriptor = serde_json::to_vec(&signed)?;
    signed
        .verify(&BTreeSet::from([signed.publisher.clone()]))
        .map_err(anyhow::Error::msg)?;
    let built = Built {
        signed,
        descriptor,
        image,
    };
    write_built(&output.join(name), &built)?;
    Ok(built)
}

#[allow(clippy::too_many_arguments)]
fn composed(
    staging: &Path,
    output: &Path,
    name: &str,
    sources: &[&Built],
    first: &BTreeMap<&str, &[u8]>,
    second: &BTreeMap<&str, &[u8]>,
    key: &[u8; 32],
    epoch: u64,
) -> Result<Built> {
    let members = first
        .iter()
        .chain(second.iter())
        .map(|(path, bytes)| (*path, *bytes))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        members.len() == first.len() + second.len(),
        "member collision"
    );
    let image = image(staging, &format!("composed-{name}"), &members, epoch)?;
    let provenance = sources
        .iter()
        .map(|source| composition::Source {
            hash: Hash::of(&source.descriptor).0,
            descriptor: String::from_utf8(source.descriptor.clone()).unwrap(),
        })
        .collect();
    let signed = composition::compose(provenance, &Hash::of(&image))
        .map_err(anyhow::Error::msg)?
        .sign(key)
        .map_err(anyhow::Error::msg)?;
    let descriptor = serde_json::to_vec(&signed)?;
    let publishers = sources
        .iter()
        .map(|s| s.signed.publisher.clone())
        .chain(std::iter::once(signed.publisher.clone()))
        .collect();
    signed.verify(&publishers).map_err(anyhow::Error::msg)?;
    let built = Built {
        signed,
        descriptor,
        image,
    };
    write_built(&output.join(name), &built)?;
    Ok(built)
}

fn write_built(directory: &Path, built: &Built) -> Result<()> {
    fs::create_dir(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    publish(
        &directory.join("signed-closure.json"),
        &built.descriptor,
        0o644,
    )?;
    publish(&directory.join("toolfs.ext2"), &built.image, 0o644)?;
    Ok(())
}

fn copy_runtime(runtime: &Path, output: &Path, pilot: &[u8], fetch: &[u8]) -> Result<()> {
    for directory in ["scripts", "guest/init", "pilot"] {
        fs::create_dir_all(output.join(directory))?;
    }
    publish(
        &output.join("scripts/mkinitramfs.sh"),
        &read_regular(&runtime.join("scripts/mkinitramfs.sh"), 1 << 20)?,
        0o700,
    )?;
    publish(
        &output.join("guest/init/init.c"),
        &read_regular(&runtime.join("guest/init/init.c"), 1 << 20)?,
        0o600,
    )?;
    publish(&output.join("pilot/celln-pilot"), pilot, 0o700)?;
    publish(&output.join("pilot/pilot-fetch"), fetch, 0o700)?;
    Ok(())
}

fn initrd(
    runtime: &Path,
    staging: &Path,
    name: &str,
    alias: &str,
    executable: &[u8],
    epoch: u64,
) -> Result<Vec<u8>> {
    let mut manifest = Manifest::new();
    manifest.admit(Entry {
        alias: alias.into(),
        hash: Hash::of(executable),
        tier: Tier::Verified,
        interpreter: false,
        author: Author::Host,
        recipe: None,
    });
    manifest.sign_standin();
    let manifest_path = staging.join(format!("{name}-manifest.json"));
    publish(&manifest_path, &serde_json::to_vec(&manifest)?, 0o600)?;
    let output = staging.join(format!("{name}.initrd"));
    let result = Command::new("/bin/bash")
        .arg(runtime.join("scripts/mkinitramfs.sh"))
        .arg(&output)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("CELLN_MANIFEST", &manifest_path)
        .env("CELLN_PILOT_DIR", runtime.join("pilot"))
        .env("CELLN_WARM_DISPATCH", "1")
        .env("SOURCE_DATE_EPOCH", epoch.to_string())
        .output()?;
    ensure!(result.status.success(), "initramfs packaging failed");
    let bytes = read_regular(&output, 64 << 20)?;
    ensure!(
        bytes.starts_with(b"070701"),
        "uncompressed newc initrd required"
    );
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn bundle(
    name: &'static str,
    entrypoint: &'static str,
    executable: &[u8],
    closure: &Built,
    source: &Built,
    initrd: &[u8],
    kernel: &[u8],
    output: &Path,
    motes: &Store,
) -> Result<Bundle> {
    let kernel_hash = motes.put(kernel)?;
    let initrd_hash = motes.put(initrd)?;
    let toolfs_hash = motes.put(&closure.image)?;
    ensure!(
        toolfs_hash.0 == closure.signed.closure.toolfs,
        "final image mismatch"
    );
    let mote_bytes = serde_json::to_vec(&json!({
        "apiVersion":"celln.dev/v1alpha1","format":"celln.warm-closure-v1",
        "kernel":kernel_hash,"initrd":initrd_hash,"toolfs":toolfs_hash,
        "invocation":{"alias":entrypoint,"toolHash":Hash::of(executable)}
    }))?;
    let mote = motes.put(&mote_bytes)?;
    let directory = output.join(name);
    publish(&directory.join("initrd"), initrd, 0o644)?;
    publish(&directory.join("mote.json"), &mote_bytes, 0o644)?;
    publish(&directory.join("executable"), executable, 0o555)?;
    Ok(Bundle {
        name,
        entrypoint,
        executable: Hash::of(executable),
        closure: Hash::of(&closure.descriptor),
        mote,
        initrd: initrd_hash,
        toolfs: toolfs_hash,
        publisher: source.signed.publisher.clone(),
        source_closure: Hash::of(&source.descriptor),
    })
}

#[allow(clippy::too_many_arguments)]
fn resources(
    revision: &str,
    bundles: &[Bundle; 3],
    one_source: &Built,
    worker_source: &Built,
    tool_source: &Built,
    input_schema: &Hash,
    output_schema: &Hash,
    source_revision: &str,
    source_tree_sha256: &str,
) -> String {
    format!(
        r#"# Generated operator catalogue metadata. Applying it is a separate privileged action.
apiVersion: sympozium.ai/v1alpha1
kind: CellnRuntimeProfile
metadata:
  name: celln-json-one-shot
  annotations:
    celln.sympozium.ai/source-revision: "{source_revision}"
    celln.sympozium.ai/source-tree-sha256: "{source_tree_sha256}"
    celln.sympozium.ai/source-closure: "{}"
spec:
  revision: {revision}
  contractVersion: celln.json-tools/v1
  executable: {{hash: "{}"}}
  closure: {{hash: "{}"}}
  mote: {{hash: "{}"}}
  publisherKey: "{}"
  entryPoint: /harness
  platform: linux/amd64
  lane: agent
  lifecycles: [disposable-one-shot]
  limits: {{timeoutMillis: 120000, memoryBytes: 134217728, taskBytes: 2048, outputBytes: 65536, workspace: none}}
  json: {{maxTurns: 6, maxCalls: 1}}
---
apiVersion: sympozium.ai/v1alpha1
kind: CellnRuntimeProfile
metadata:
  name: celln-json-enduring
  annotations:
    celln.sympozium.ai/source-revision: "{source_revision}"
    celln.sympozium.ai/source-tree-sha256: "{source_tree_sha256}"
    celln.sympozium.ai/source-closure: "{}"
spec:
  revision: {revision}
  contractVersion: celln.json-tools/v1
  executable: {{hash: "{}"}}
  closure: {{hash: "{}"}}
  mote: {{hash: "{}"}}
  publisherKey: "{}"
  entryPoint: /worker
  platform: linux/amd64
  lane: agent
  lifecycles: [enduring]
  limits: {{timeoutMillis: 120000, memoryBytes: 134217728, taskBytes: 2048, outputBytes: 65536, workspace: none}}
  json: {{maxTurns: 6, maxCalls: 1}}
---
apiVersion: sympozium.ai/v1alpha1
kind: ClusterCellnTool
metadata:
  name: uppercase
  annotations:
    celln.sympozium.ai/source-revision: "{source_revision}"
    celln.sympozium.ai/source-tree-sha256: "{source_tree_sha256}"
spec:
  revision: {revision}
  description: Uppercase one bounded JSON string using Unicode uppercase semantics.
  supportOwner: platform-operator
  publisherKey: "{}"
  executable: {{hash: "{}"}}
  closure: {{hash: "{}"}}
  entryPoint: /uppercase
  invocationABI: celln.json-stdio/v1
  argumentsSchema: {{hash: "{}"}}
  resultSchema: {{hash: "{}"}}
  platform: linux/amd64
  lane: tool
  limits: {{timeoutMillis: 5000, memoryBytes: 134217728, argumentBytes: 4096, outputBytes: 4096, workspace: none, effects: none}}
"#,
        Hash::of(&one_source.descriptor),
        bundles[0].executable,
        bundles[0].closure,
        bundles[0].mote,
        one_source.signed.publisher,
        Hash::of(&worker_source.descriptor),
        bundles[1].executable,
        bundles[1].closure,
        bundles[1].mote,
        worker_source.signed.publisher,
        tool_source.signed.publisher,
        tool_source.signed.closure.members["/uppercase"].hash,
        Hash::of(&tool_source.descriptor),
        input_schema,
        output_schema,
    )
}

fn write_manifest(root: &Path) -> Result<()> {
    fn visit(root: &Path, directory: &Path, entries: &mut Vec<(PathBuf, Hash)>) -> Result<()> {
        let mut paths = fs::read_dir(directory)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        for path in paths {
            if path == root.join("MANIFEST.blake3") {
                continue;
            }
            if path.is_dir() {
                visit(root, &path, entries)?;
            } else {
                entries.push((
                    path.strip_prefix(root)?.to_owned(),
                    Hash::of(&fs::read(&path)?),
                ));
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries)?;
    let text = entries
        .iter()
        .map(|(path, hash)| format!("{}  {}\n", &hash.0[7..], path.display()))
        .collect::<String>();
    publish(&root.join("MANIFEST.blake3"), text.as_bytes(), 0o644)
}

fn normalize_modes(root: &Path) -> Result<()> {
    fn visit(path: &Path) -> Result<()> {
        if path.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
            for entry in fs::read_dir(path)? {
                visit(&entry?.path())?;
            }
        } else {
            let mode = if path.file_name().is_some_and(|name| name == "executable") {
                0o555
            } else {
                0o444
            };
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
        Ok(())
    }
    visit(root)
}
