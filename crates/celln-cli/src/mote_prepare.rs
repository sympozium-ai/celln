//! Cold-path packaging only. An exact template is an operator input, not an
//! execution grant. No host-kernel discovery, trust-policy writes or guest boot.
use anyhow::{ensure, Context, Result};
use celln_manifest::Hash;
use celln_store::Store;
use serde::Deserialize;
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Template {
    api_version: String,
    kernel: String,
    initrd: String,
    runtime_executable: String,
    runtime_entry_point: String,
    composer_publisher: String,
}

fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("opening preparation input")?;
    ensure!(
        file.metadata()?.is_file(),
        "regular preparation input required"
    );
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= limit,
        "input empty or oversized"
    );
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    template_path: &Path,
    expected_template: &str,
    descriptor: &Path,
    toolfs: &Path,
    mote_store: &Path,
    output: &Path,
    root: &Path,
) -> Result<u8> {
    let template_bytes = read_regular(template_path, 16384)?;
    ensure!(
        Hash::of(&template_bytes).0 == expected_template,
        "template identity mismatch"
    );
    let template: Template = serde_json::from_slice(&template_bytes)?;
    ensure!(
        template.api_version == "celln.dev/mote-template-v1",
        "unsupported template"
    );
    let raw = read_regular(descriptor, crate::closure_policy::MAX_DESCRIPTOR_BYTES)?;
    let verified = crate::closure_policy::verify(&raw, root).map_err(anyhow::Error::msg)?;
    let closure = &verified.signed.closure;
    ensure!(
        verified.signed.publisher == template.composer_publisher,
        "template composer mismatch"
    );
    ensure!(
        closure.entrypoint == template.runtime_entry_point
            && closure
                .members
                .get(&closure.entrypoint)
                .is_some_and(|m| m.hash == template.runtime_executable),
        "template runtime mismatch"
    );
    let image = read_regular(toolfs, crate::image::MAX_IMAGE_BYTES as usize)?;
    ensure!(
        Hash::of(&image).0 == closure.toolfs,
        "signed filesystem mismatch"
    );
    // Store::open may create the store directory, but never changes admission.
    let store = Store::open(mote_store)?;
    let kernel = store.get_bounded(&Hash(template.kernel.clone()), 64 << 20)?;
    let initrd = store.get_bounded(&Hash(template.initrd.clone()), 64 << 20)?;
    ensure!(
        !kernel.is_empty() && initrd.starts_with(b"070701"),
        "nonempty kernel and uncompressed newc initrd required"
    );
    let bundle = serde_json::to_vec(
        &json!({"apiVersion":"celln.dev/v1alpha1","format":"celln.warm-closure-v1","kernel":template.kernel,"initrd":template.initrd,"toolfs":closure.toolfs,"invocation":{"alias":closure.entrypoint,"toolHash":template.runtime_executable}}),
    )?;
    let current = crate::closure_policy::verify(&raw, root).map_err(anyhow::Error::msg)?;
    ensure!(
        current.policy_hash == verified.policy_hash,
        "policy changed during preparation"
    );
    // Never replace an output directory, admit a derived mote or infer trust
    // from content addressing. Partial output remains visibly incomplete.
    fs::create_dir(output).context("output must be a new directory")?;
    for (name, bytes) in [
        ("kernel", kernel.as_slice()),
        ("initrd", initrd.as_slice()),
        ("toolfs.ext2", image.as_slice()),
        ("signed-closure.json", raw.as_slice()),
        ("mote.json", bundle.as_slice()),
        ("template.json", template_bytes.as_slice()),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    let report = json!({"apiVersion":"celln.dev/mote-preparation-v1","template":expected_template,"mote":{"hash":Hash::of(&bundle).0},"closure":{"hash":verified.identity.0},"policyHash":verified.policy_hash.0,"admitted":false,"hardwareConformance":"not_checked","readiness":"not_established","executionAuthorized":false});
    let mut completion = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("prepared.json"))?;
    completion.write_all(&serde_json::to_vec(&report)?)?;
    completion.sync_all()?;
    #[cfg(unix)]
    fs::File::open(output)?.sync_all()?;
    println!("{}", report);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_manifest::closure::{Closure, Member};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn preparation_binds_inputs_and_never_admits() {
        for mode in [
            "valid",
            "runtime",
            "composer",
            "image",
            "revoked",
            "missing-kernel",
            "existing-output",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let store = Store::open(root.join("motes")).unwrap();
            let kernel = store.put(b"reviewed test kernel bytes").unwrap();
            let initrd = store.put(b"070701reviewed test archive bytes").unwrap();
            let executable = Hash::of(b"runtime").0;
            let signed = Closure {
                api_version: "celln.dev/closure-v1".into(),
                sources: vec![],
                toolfs: Hash::of(b"image").0,
                entrypoint: "/harness".into(),
                interpreter: false,
                members: BTreeMap::from([(
                    "/harness".into(),
                    Member {
                        hash: executable.clone(),
                        dependencies: BTreeSet::new(),
                    },
                )]),
            }
            .sign(&[42; 32])
            .unwrap();
            let raw = serde_json::to_vec(&signed).unwrap();
            let mut template = json!({"apiVersion":"celln.dev/mote-template-v1","kernel":kernel.0,"initrd":initrd.0,"runtimeExecutable":executable,"runtimeEntryPoint":"/harness","composerPublisher":signed.publisher});
            if mode == "runtime" {
                template["runtimeExecutable"] = Hash::of(b"different").0.into();
            }
            if mode == "composer" {
                template["composerPublisher"] = "different".into();
            }
            if mode == "missing-kernel" {
                template["kernel"] = Hash::of(b"missing").0.into();
            }
            let template = serde_json::to_vec(&template).unwrap();
            let revoked: Vec<_> = if mode == "revoked" {
                vec![Hash::of(&raw).0]
            } else {
                vec![]
            };
            let policy = serde_json::to_vec(&json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":revoked})).unwrap();
            fs::write(root.join("trusted-closures.json"), &policy).unwrap();
            fs::write(root.join("trusted-motes.json"), b"operator-owned sentinel").unwrap();
            fs::write(root.join("template"), &template).unwrap();
            fs::write(root.join("descriptor"), &raw).unwrap();
            fs::write(
                root.join("image"),
                if mode == "image" { b"other" } else { b"image" },
            )
            .unwrap();
            let output = root.join("out");
            if mode == "existing-output" {
                fs::create_dir(&output).unwrap();
            }
            let result = run(
                &root.join("template"),
                &Hash::of(&template).0,
                &root.join("descriptor"),
                &root.join("image"),
                &root.join("motes"),
                &output,
                root,
            );
            assert_eq!(result.is_ok(), mode == "valid", "{mode}: {result:?}");
            assert_eq!(
                fs::read(root.join("trusted-motes.json")).unwrap(),
                b"operator-owned sentinel"
            );
            assert_eq!(
                fs::read(root.join("trusted-closures.json")).unwrap(),
                policy
            );
            assert!(!root.join("closures").exists());
            if mode == "valid" {
                let report: serde_json::Value =
                    serde_json::from_slice(&fs::read(output.join("prepared.json")).unwrap())
                        .unwrap();
                assert_eq!(report["admitted"], false);
                assert_eq!(report["executionAuthorized"], false);
                assert_eq!(
                    report["mote"]["hash"],
                    Hash::of(&fs::read(output.join("mote.json")).unwrap()).0
                );
                assert_eq!(
                    fs::read(output.join("kernel")).unwrap(),
                    b"reviewed test kernel bytes"
                );
            } else {
                assert!(!output.join("prepared.json").exists());
            }
        }
    }
    #[test]
    fn bounded_regular_inputs_and_template_pin_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("template");
        fs::write(&file, b"{}").unwrap();
        assert!(read_regular(&file, 1).is_err());
        assert!(read_regular(dir.path(), 100).is_err());
        assert!(run(
            &file,
            "wrong",
            &file,
            &file,
            dir.path(),
            &dir.path().join("out"),
            dir.path()
        )
        .is_err());
        assert!(!dir.path().join("out").exists());
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(read_regular(&link, 100).is_err());
        }
    }
}
