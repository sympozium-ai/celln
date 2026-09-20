//! Explicit host admission of a reviewed package. Publisher approval must
//! already exist; package metadata never installs its own trust policy.
use crate::starter_package::regular;
use anyhow::{ensure, Context, Result};
use celln_manifest::{closure::SignedClosure, Hash};
use celln_store::Store;
use serde_json::{json, Value};
use std::{fs, path::Path};

const NAMES: &[&str] = &[
    "parent",
    "worker",
    "workspace-read",
    "workspace-write",
    "https-fetch",
    "workspace-list",
    "workspace-append",
    "workspace-search",
    "workspace-delete",
    "https-post-json",
];

pub(crate) struct Candidate {
    name: String,
    kernel: Vec<u8>,
    initrd: Vec<u8>,
    image: Vec<u8>,
    descriptor: Vec<u8>,
    executable: Vec<u8>,
    template: Vec<u8>,
    mote: String,
}

pub(crate) fn verified(package: &Path, expected: &str, root: &Path) -> Result<Vec<Candidate>> {
    ensure!(
        package.is_absolute() && root.is_absolute() && root.is_dir(),
        "absolute package and existing authority root required"
    );
    let raw = regular(&package.join("package.json"), 65536)?;
    ensure!(
        Hash::of(&raw).0 == expected,
        "package differs from explicit administrator approval"
    );
    let report: Value = serde_json::from_slice(&raw)?;
    ensure!(
        report["apiVersion"] == "celln.native-starter-package/v1",
        "unsupported starter package"
    );
    let entries = report["bundles"]
        .as_array()
        .context("package bundles required")?;
    let has_runtime = entries.iter().any(|entry| entry["name"] == "runtime");
    ensure!(
        entries.len() == NAMES.len() + usize::from(has_runtime),
        "exact starter bundles (and optional isolated runtime) required"
    );
    let kernel = regular(&package.join("kernel"), 64 << 20)?;
    ensure!(
        report["kernel"] == Hash::of(&kernel).0,
        "kernel hash mismatch"
    );
    let mut candidates = Vec::new();
    for name in NAMES
        .iter()
        .copied()
        .chain(has_runtime.then_some("runtime"))
    {
        let matching: Vec<_> = entries
            .iter()
            .filter(|entry| entry["name"] == name)
            .collect();
        ensure!(
            matching.len() == 1,
            "unique expected package bundle required"
        );
        let entry = matching[0];
        // Names come from this compiled list, never paths in uploaded metadata.
        let directory = package.join(name);
        let descriptor = regular(
            &directory.join("signed-closure.json"),
            crate::closure_policy::MAX_DESCRIPTOR_BYTES,
        )?;
        let checked =
            crate::closure_policy::verify(&descriptor, root).map_err(anyhow::Error::msg)?;
        let signed: &SignedClosure = &checked.signed;
        ensure!(
            entry["publisher"] == signed.publisher && entry["closure"] == checked.identity.0,
            "approved closure identity mismatch"
        );
        let image = regular(&directory.join("toolfs.ext2"), 64 << 20)?;
        let initrd = regular(&directory.join("initrd"), 64 << 20)?;
        let executable = regular(&directory.join("executable"), 64 << 20)?;
        let mote = regular(&directory.join("mote.json"), 16384)?;
        for (bytes, field) in [
            (&image, "toolfs"),
            (&initrd, "initrd"),
            (&executable, "executable"),
            (&mote, "mote"),
        ] {
            ensure!(
                entry[field] == Hash::of(bytes).0,
                "package artifact hash mismatch: {name}/{field}"
            );
        }
        let alias = if name == "runtime" {
            "/worker".into()
        } else {
            format!("/{name}")
        };
        ensure!(
            entry["entryPoint"] == alias && signed.closure.entrypoint == alias,
            "unexpected starter entrypoint"
        );
        ensure!(
            signed.closure.toolfs == Hash::of(&image).0
                && signed
                    .closure
                    .members
                    .get(&alias)
                    .is_some_and(|member| member.hash == Hash::of(&executable).0),
            "signed member identity mismatch"
        );
        let template = serde_json::to_vec(&json!({
            "apiVersion":"celln.dev/mote-template-v1", "kernel":Hash::of(&kernel),
            "initrd":Hash::of(&initrd), "runtimeExecutable":Hash::of(&executable),
            "runtimeEntryPoint":alias, "composerPublisher":signed.publisher
        }))?;
        // Reconstruct the descriptor; fields in mote.json confer no authority.
        let derived = serde_json::to_vec(
            &json!({"apiVersion":"celln.dev/v1alpha1", "format":"celln.warm-closure-v1", "kernel":Hash::of(&kernel), "initrd":Hash::of(&initrd), "toolfs":Hash::of(&image), "invocation":{"alias":alias,"toolHash":Hash::of(&executable)}}),
        )?;
        ensure!(
            derived == mote,
            "mote descriptor differs from verified inputs"
        );
        candidates.push(Candidate {
            name: name.into(),
            kernel: kernel.clone(),
            initrd,
            image,
            descriptor,
            executable,
            template,
            mote: Hash::of(&mote).0,
        });
    }
    Ok(candidates)
}

pub fn run(package: &Path, expected: &str, root: &Path) -> Result<u8> {
    // All package bytes/signatures are verified before store or policy writes.
    let candidates = verified(package, expected, root)?;
    let motes = Store::open(root.join("motes"))?;
    let tools = Store::open(root.join("tools"))?;
    let mut reports = Vec::new();
    for candidate in candidates {
        motes.put(&candidate.kernel)?;
        motes.put(&candidate.initrd)?;
        tools.put(&candidate.executable)?;
        let stage = tempfile::tempdir()?;
        for (name, bytes) in [
            ("template.json", &candidate.template),
            ("signed-closure.json", &candidate.descriptor),
            ("toolfs.ext2", &candidate.image),
        ] {
            fs::write(stage.path().join(name), bytes)?;
        }
        let report = crate::mote_admit::admit(stage.path(), &Hash::of(&candidate.template).0, &candidate.mote, &root.join("motes"), &root.join("tools"), root)
            .with_context(|| format!("admitting {}; preserve existing policy and evidence, earlier bundle admissions may have completed", candidate.name))?;
        reports.push(json!({"name":candidate.name,"admission":report}));
    }
    println!(
        "{}",
        json!({"apiVersion":"celln.native-starter-admission/v1","packageHash":expected,"bundles":reports,"executionAuthorized":false,"readiness":"not_established"})
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "explicit KVM guest-member admission check with built native guest binaries; no model"]
    fn admits_only_reviewed_package_through_guest_member_checks() {
        assert!(Path::new("/dev/kvm").exists(), "KVM required");
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let guest = repo.join("target/x86_64-unknown-linux-musl/release");
        let kernel =
            warden::vmm::boot::BootConfig::host_kernel().expect("readable kernel required");
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("package");
        let key = dir.path().join("key");
        fs::write(&key, [19u8; 32]).unwrap();
        let report = crate::starter_package::prepare(
            &repo,
            &guest,
            &kernel,
            &key,
            &package,
            &Default::default(),
            &[],
        )
        .unwrap();
        let expected = Hash::of(&fs::read(package.join("package.json")).unwrap()).0;
        let root = dir.path().join("authority");
        fs::create_dir(&root).unwrap();
        // Neither missing publisher policy nor a substituted descriptor may
        // create store objects, even when metadata has an approved package hash.
        assert!(run(&package, &expected, &root).is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::write(root.join("trusted-closures.json"), serde_json::to_vec(&json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[report["bundles"][0]["publisher"]],"revoked":[]})).unwrap()).unwrap();
        let descriptor = package.join("https-fetch/signed-closure.json");
        let original = fs::read(&descriptor).unwrap();
        fs::write(&descriptor, b"{}").unwrap();
        assert!(run(&package, &expected, &root).is_err());
        assert!(!root.join("motes").exists());
        fs::write(descriptor, original).unwrap();
        assert_eq!(run(&package, &expected, &root).unwrap(), 0);
        let policy: Value =
            serde_json::from_slice(&fs::read(root.join("trusted-motes.json")).unwrap()).unwrap();
        assert_eq!(policy["bundles"].as_array().unwrap().len(), 11);
        for entry in report["bundles"].as_array().unwrap() {
            assert!(policy["bundles"]
                .as_array()
                .unwrap()
                .contains(&entry["mote"]));
        }
        assert!(!root.join("trusted-parent-permits").exists());
        let configured = dir.path().join("configured");
        let config_plan = dir.path().join("config-plan.json");
        fs::write(&config_plan, serde_json::to_vec(&json!({"apiVersion":"celln.native-starter-config/v1","package":package,"packageHash":expected,"principal":"operator:native-test","credentialFile":"/etc/celln-native/not-read-test-token","output":configured})).unwrap()).unwrap();
        assert_eq!(
            crate::starter_configure::run(&config_plan, &root).unwrap(),
            0
        );
        let catalogue: Value =
            serde_json::from_slice(&fs::read(configured.join("catalogue.json")).unwrap()).unwrap();
        let runtime = report["bundles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == "runtime")
            .unwrap();
        assert_eq!(catalogue["worker"]["closure"]["hash"], runtime["closure"]);
        assert_eq!(catalogue["worker"]["mote"]["hash"], runtime["mote"]);
        assert!(!root.join("trusted-parent-permits").exists());
        assert!(crate::starter_configure::run(&config_plan, &root).is_err());
        // The reviewed parent is also written as the scoped receiver's parent
        // request, which `--scoped-parent-request-file` accepts as it stands.
        let scoped_parent = fs::read(configured.join("scoped-parent-request.json")).unwrap();
        let template: Value = serde_json::from_slice(&scoped_parent).unwrap();
        let reviewed: Value =
            serde_json::from_slice(&fs::read(configured.join("native-template.json")).unwrap())
                .unwrap();
        assert_eq!(
            template,
            crate::starter_configure::scoped_parent_request(
                &serde_json::from_value(reviewed["parent"].clone()).unwrap()
            )
        );
        assert_eq!(
            template["reservedMemoryBytes"],
            reviewed["reservedMemoryBytes"]
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            crate::dispatch_http::parent_request_file_accepted(dir.path(), &scoped_parent),
            Ok(())
        );
        // Reviewed defaults are published as the host ceilings.
        let receipt: Value =
            serde_json::from_slice(&fs::read(configured.join("configured.json")).unwrap()).unwrap();
        assert_eq!(receipt["hostLimits"]["leaseSeconds"], 3600);
        assert_eq!(receipt["hostLimits"]["maxTurns"], 12);
        // Operator host limits reach the parent lifetime, the native
        // template totals and the receipt; out-of-range values are refused
        // before anything is written.
        let long_lived = dir.path().join("configured-long");
        let long_plan = dir.path().join("config-plan-long.json");
        let mut plan: Value = serde_json::from_slice(&fs::read(&config_plan).unwrap()).unwrap();
        plan["output"] = json!(long_lived);
        plan["hostLimits"] = json!({"leaseSeconds": 86400, "maxTurns": 256, "maxModelRequests": 1536, "maxOutputTokens": 786432});
        fs::write(&long_plan, serde_json::to_vec(&plan).unwrap()).unwrap();
        assert_eq!(crate::starter_configure::run(&long_plan, &root).unwrap(), 0);
        let native: Value =
            serde_json::from_slice(&fs::read(long_lived.join("native-template.json")).unwrap())
                .unwrap();
        assert_eq!(native["parent"]["capabilities"]["timeoutMs"], 86_400_000);
        assert_eq!(native["maxTurns"], 256);
        assert_eq!(native["totalModelRequests"], 1536);
        assert_eq!(native["totalOutputTokens"], 786432);
        // Each turn affords the template's whole model loop: six requests
        // of 512 tokens, enough for four tool calls one at a time.
        assert_eq!(native["turnModelRequests"], 6);
        assert_eq!(native["turnOutputTokens"], 3072);
        assert_eq!(native["template"]["max_turns"], 6);
        assert_eq!(native["template"]["max_calls"], 4);
        let receipt: Value =
            serde_json::from_slice(&fs::read(long_lived.join("configured.json")).unwrap()).unwrap();
        assert_eq!(receipt["hostLimits"]["leaseSeconds"], 86400);
        // A backend cap scales the turn allowance and the default totals,
        // reaches the worker template and the pinned profile, and is stated
        // in the receipt; the default plan above named none of it.
        assert!(receipt["model"].get("maxOutputTokens").is_none());
        assert!(native["template"].get("max_tokens").is_none());
        let roomy = dir.path().join("configured-roomy");
        let roomy_plan = dir.path().join("config-plan-roomy.json");
        let mut capped: Value = serde_json::from_slice(&fs::read(&config_plan).unwrap()).unwrap();
        capped["output"] = json!(roomy);
        capped["modelConnection"] = json!({"provider":"llama-server","protocol":"openai-chat",
            "endpoint":"http://10.0.0.5:8080/v1/chat/completions","model":"qwen",
            "credentialProfile":"local","allowInsecure":true,"maxOutputTokens":2048});
        fs::write(&roomy_plan, serde_json::to_vec(&capped).unwrap()).unwrap();
        assert_eq!(
            crate::starter_configure::run(&roomy_plan, &root).unwrap(),
            0
        );
        let native: Value =
            serde_json::from_slice(&fs::read(roomy.join("native-template.json")).unwrap()).unwrap();
        assert_eq!(native["template"]["max_tokens"], 2048);
        assert_eq!(native["turnModelRequests"], 6);
        assert_eq!(native["turnOutputTokens"], 12288);
        assert_eq!(native["totalOutputTokens"], 147_456);
        let receipt: Value =
            serde_json::from_slice(&fs::read(roomy.join("configured.json")).unwrap()).unwrap();
        assert_eq!(receipt["model"]["maxOutputTokens"], 2048);
        assert_eq!(receipt["hostLimits"]["maxOutputTokens"], 147_456);
        let pinned = native["modelProfile"].as_str().unwrap();
        let profile: Value = serde_json::from_slice(
            &fs::read(
                root.join("trusted-parent-models")
                    .join(format!("{}.json", &pinned[7..])),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(profile["maxOutputTokens"], 2048);
        assert_eq!(profile["maxTotalOutputTokens"], 12288);
        let bad = dir.path().join("configured-bad");
        let bad_plan = dir.path().join("config-plan-bad.json");
        plan["output"] = json!(bad);
        plan["hostLimits"] = json!({"leaseSeconds": 86401});
        fs::write(&bad_plan, serde_json::to_vec(&plan).unwrap()).unwrap();
        assert!(crate::starter_configure::run(&bad_plan, &root).is_err());
        assert!(!bad.exists());
        for name in [
            "parent-issuance",
            "trusted-parent-permits",
            "trusted-parent-launches",
        ] {
            fs::create_dir(root.join(name)).unwrap();
        }
        let mut provision: Value =
            serde_json::from_slice(&fs::read(configured.join("native-template.json")).unwrap())
                .unwrap();
        provision["apiVersion"] = json!("celln.parent-provision-plan/v1");
        provision["scope"] = json!("native-installation-test");
        provision["runUid"] = json!("test-installation-run-uid");
        provision["intentSHA256"] = json!(format!("sha256:{}", "a".repeat(64)));
        let provision_path = dir.path().join("provision.json");
        fs::write(&provision_path, serde_json::to_vec(&provision).unwrap()).unwrap();
        assert_eq!(
            crate::dispatch::parent_create::provision_file(
                &root,
                &provision_path,
                "operator:native-test"
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn mismatch_refuses_before_store_creation() {
        let directory = tempfile::tempdir().unwrap();
        let package = directory.path().join("package");
        let root = directory.path().join("authority");
        fs::create_dir(&package).unwrap();
        fs::create_dir(&root).unwrap();
        let raw = br#"{"apiVersion":"celln.native-starter-package/v1","bundles":[]}"#;
        fs::write(package.join("package.json"), raw).unwrap();
        assert!(run(&package, &Hash::of(b"other").0, &root).is_err());
        assert!(run(&package, &Hash::of(raw).0, &root).is_err());
        assert_eq!(fs::read_dir(root).unwrap().count(), 0);
    }
}
