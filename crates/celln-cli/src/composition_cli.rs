//! Operator-side packaging; never runs source members or mounts input images.
use anyhow::Result;
use std::path::Path;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use celln_manifest::{
        closure::{Closure, Member},
        Hash,
    };
    use celln_store::Store;
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
    };

    #[test]
    fn composition_builds_real_image_and_source_revocation_survives_signing() {
        let builder = Path::new("/usr/sbin/mke2fs");
        if !builder.is_file() {
            eprintln!("SKIP: mke2fs unavailable");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let members = Store::open(root.join("tools")).unwrap();
        let descriptors = Store::open(root.join("closures")).unwrap();
        let mut sources = Vec::new();
        let mut publishers = BTreeSet::new();
        let mut filesystem = String::new();
        for (path, seed) in [("/harness", 1), ("/tools/tool", 2)] {
            let hash = members.put(path.as_bytes()).unwrap();
            let source = Closure {
                api_version: "celln.dev/closure-v1".into(),
                toolfs: Hash::of(format!("source filesystem {seed}").as_bytes()).0,
                entrypoint: path.into(),
                interpreter: false,
                members: BTreeMap::from([(
                    path.into(),
                    Member {
                        hash: hash.0,
                        dependencies: BTreeSet::new(),
                    },
                )]),
                sources: vec![],
            }
            .sign(&[seed; 32])
            .unwrap();
            filesystem = source.closure.toolfs.clone();
            publishers.insert(source.publisher.clone());
            sources.push(
                descriptors
                    .put(&serde_json::to_vec(&source).unwrap())
                    .unwrap()
                    .0,
            );
        }
        // Use the runtime publisher as the independently authorized composer.
        let key = root.join("key");
        fs::write(&key, [1; 32]).unwrap();
        let policy = root.join("trusted-closures.json");
        let write_policy = |revoked: Vec<String>, allowed: &BTreeSet<String>| {
            fs::write(
                &policy,
                serde_json::to_vec(
                    &serde_json::json!({"apiVersion":"celln.dev/closure-policy-v1",
                "publishers":allowed,"revoked":revoked}),
                )
                .unwrap(),
            )
            .unwrap();
        };
        write_policy(vec![], &publishers);
        let plan = root.join("plan.json");
        fs::write(
            &plan,
            serde_json::to_vec(
                &serde_json::json!({"apiVersion":"celln.dev/composition-plan-v1",
            "sources":sources,"imageBytes":33554432}),
            )
            .unwrap(),
        )
        .unwrap();
        let output = root.join("output");
        let report = build(&plan, &key, &output, builder, root).unwrap();
        let image = fs::read(output.join("toolfs.ext2")).unwrap();
        assert_eq!(image.len(), 33554432);
        assert_eq!(&image[1080..1082], &[0x53, 0xef]); // ext2 superblock magic
        assert_eq!(report["toolfs"], Hash::of(&image).0);
        let descriptor = fs::read(output.join("signed-closure.json")).unwrap();
        crate::closure_policy::verify(&descriptor, root).unwrap();
        assert!(build(&plan, &key, &output, builder, root).is_err());
        assert_eq!(
            fs::read(output.join("signed-closure.json")).unwrap(),
            descriptor
        );
        for revoked in [sources[1].clone(), filesystem, Hash::of(b"/tools/tool").0] {
            write_policy(vec![revoked], &publishers);
            assert!(crate::closure_policy::verify(&descriptor, root).is_err());
        }
        let source = descriptors.get(&Hash(sources[1].clone())).unwrap();
        let source: celln_manifest::closure::SignedClosure =
            serde_json::from_slice(&source).unwrap();
        publishers.remove(&source.publisher);
        write_policy(vec![], &publishers);
        assert!(crate::closure_policy::verify(&descriptor, root).is_err());
        assert!(build(&plan, &key, &root.join("refused"), builder, root).is_err());
        assert!(!root.join("refused").exists());
    }
}

pub fn run(plan: &Path, key: &Path, output: &Path, builder: &Path, root: &Path) -> Result<u8> {
    #[cfg(target_os = "linux")]
    {
        let report = build(plan, key, output, builder, root)?;
        println!("{}", serde_json::to_string(&report)?);
        Ok(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plan, key, output, builder, root);
        anyhow::bail!("Unsupported: closure composition requires Linux")
    }
}

#[cfg(target_os = "linux")]
fn build(
    plan: &Path,
    key: &Path,
    output: &Path,
    builder: &Path,
    root: &Path,
) -> Result<serde_json::Value> {
    use anyhow::ensure;
    use celln_manifest::{
        closure::composition::{compose, Source},
        Hash,
    };
    use celln_store::Store;
    use std::{
        fs,
        io::{Read, Write},
        os::unix::fs::PermissionsExt,
        time::Duration,
    };

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Plan {
        api_version: String,
        sources: Vec<String>,
        image_bytes: usize,
    }
    let bytes = crate::closure_policy::read_bounded(plan).map_err(anyhow::Error::msg)?;
    ensure!(bytes.len() <= 65536, "composition plan exceeds 64 KiB");
    let plan: Plan = serde_json::from_slice(&bytes)?;
    ensure!(
        plan.api_version == "celln.dev/composition-plan-v1",
        "unsupported composition plan"
    );
    ensure!(
        !plan.sources.is_empty() && plan.sources.len() <= 17,
        "expected runtime and at most 16 tools"
    );
    ensure!(
        (32 * 1024 * 1024..=512 * 1024 * 1024).contains(&plan.image_bytes)
            && plan.image_bytes % (2 * 1024 * 1024) == 0,
        "image must be 32..512 MiB and 2 MiB aligned"
    );
    ensure!(
        builder.is_absolute(),
        "builder must be an absolute trusted operator path"
    );
    let descriptors = Store::open(root.join("closures"))?;
    let mut sources = Vec::new();
    let mut policy_hash = None;
    for hash in &plan.sources {
        let descriptor = descriptors.get_bounded(&Hash(hash.clone()), 262144)?;
        let verified =
            crate::closure_policy::verify(&descriptor, root).map_err(anyhow::Error::msg)?;
        if let Some(previous) = &policy_hash {
            ensure!(
                previous == &verified.policy_hash,
                "policy changed during composition"
            );
        }
        policy_hash = Some(verified.policy_hash);
        sources.push(Source {
            hash: hash.clone(),
            descriptor: String::from_utf8(descriptor)?,
        });
    }
    let graph =
        compose(sources.clone(), &Hash::of(b"pending image")).map_err(anyhow::Error::msg)?;
    // Check the signing key and composer authorization before running the builder.
    let provisional = crate::closure_cli::sign_descriptor(graph.clone(), key)?;
    crate::closure_policy::verify(&serde_json::to_vec(&provisional)?, root)
        .map_err(anyhow::Error::msg)?;
    for path in graph.members.keys() {
        ensure!(
            path != "/tmp"
                && !path.starts_with("/tmp/")
                && path != "/lost+found"
                && !path.starts_with("/lost+found/"),
            "member uses reserved filesystem path"
        );
    }
    // Fail if the destination exists. Its private permissions protect staging
    // from another local user substituting a symlink during construction.
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(output)?;
    let output = fs::canonicalize(output)?;
    let staging = tempfile::Builder::new()
        .prefix("members-")
        .tempdir_in(&output)?;
    let store = Store::open(root.join("tools"))?;
    let mut remaining = plan.image_bytes - 8 * 1024 * 1024;
    for (path, member) in &graph.members {
        let data = store.get_bounded(&Hash(member.hash.clone()), remaining)?;
        remaining -= data.len();
        let target = staging.path().join(path.trim_start_matches('/'));
        fs::create_dir_all(target.parent().unwrap())?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        file.write_all(&data)?;
        file.set_permissions(fs::Permissions::from_mode(0o555))?;
    }
    fs::create_dir(staging.path().join("tmp"))?;
    fs::set_permissions(
        staging.path().join("tmp"),
        fs::Permissions::from_mode(0o1777),
    )?;
    let image = output.join("toolfs.ext2");
    let image_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&image)?;
    image_file.set_len(plan.image_bytes as u64)?;
    let args = vec![
        "-q".into(),
        "-t".into(),
        "ext2".into(),
        "-b".into(),
        "4096".into(),
        "-m".into(),
        "0".into(),
        "-d".into(),
        staging
            .path()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non UTF-8 staging path"))?
            .into(),
        "-F".into(),
        image
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non UTF-8 image path"))?
            .into(),
        (plan.image_bytes / 4096).to_string(),
    ];
    pilot::harness_io::child(
        builder
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non UTF-8 builder path"))?,
        &args,
        &[],
        65536,
        Duration::from_secs(45),
    )?;
    let mut image_bytes = Vec::new();
    fs::File::open(&image)?
        .take(plan.image_bytes as u64 + 1)
        .read_to_end(&mut image_bytes)?;
    ensure!(
        image_bytes.len() == plan.image_bytes,
        "builder changed image size"
    );
    let toolfs = Hash::of(&image_bytes);
    image_file.sync_all()?;
    let closure = compose(sources, &toolfs).map_err(anyhow::Error::msg)?;
    let signed = crate::closure_cli::sign_descriptor(closure, key)?;
    let descriptor = serde_json::to_vec(&signed)?;
    let verified = crate::closure_policy::verify(&descriptor, root).map_err(anyhow::Error::msg)?;
    ensure!(
        Some(&verified.policy_hash) == policy_hash.as_ref(),
        "policy changed during composition"
    );
    // Descriptor is the final publication marker. A failed build leaves only
    // an explicitly named diagnostic directory, never an admitted artifact.
    let mut file = tempfile::NamedTempFile::new_in(&output)?;
    file.write_all(&descriptor)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(output.join("signed-closure.json"))?;
    fs::File::open(&output)?.sync_all()?;
    Ok(
        serde_json::json!({"apiVersion":"celln.dev/composition-report-v1", "planHash":Hash::of(&bytes).0,
        "policyHash":verified.policy_hash.0, "closure":verified.identity.0,"toolfs":toolfs.0,
        "sources":plan.sources,"artifactReadiness":"not_checked","conformance":"not_checked"}),
    )
}
