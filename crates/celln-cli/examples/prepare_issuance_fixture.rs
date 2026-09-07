//! Explicit public-seed test-store materialization, not production admission.
use anyhow::{ensure, Result};
use celln_manifest::{closure::SignedClosure, Hash};
use celln_store::Store;
use serde_json::json;
use std::{collections::BTreeSet, fs, io::Write, path::PathBuf};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: prepare_issuance_fixture PUBLIC_FIXTURE_ROOT COMPOSED_DIRECTORY JSON_PACKAGE"
    );
    let root = PathBuf::from(&args[1]);
    let composed = PathBuf::from(&args[2]);
    let package = PathBuf::from(&args[3]);
    ensure!(
        fs::read(root.join("public-fixture-seed"))? == [42; 32],
        "public test fixture required"
    );
    ensure!(
        !root.join("trusted-motes.json").exists(),
        "refusing to replace existing mote policy"
    );
    let raw = fs::read(composed.join("signed-closure.json"))?;
    let signed: SignedClosure = serde_json::from_slice(&raw)?;
    let catalogue: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("catalogue.json"))?)?;
    let publisher = catalogue["runtimeSpec"]["celln"]["publisherKey"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing fixture publisher"))?;
    signed
        .verify(&BTreeSet::from([publisher.to_owned()]))
        .map_err(anyhow::Error::msg)?;
    let image = fs::read(composed.join("toolfs.ext2"))?;
    ensure!(
        Hash::of(&image).0 == signed.closure.toolfs,
        "image differs from signed composition"
    );
    let runtime = &signed.closure.members[&signed.closure.entrypoint].hash;
    ensure!(
        Hash::of(&fs::read(package.join("harness"))?).0 == *runtime,
        "package runtime differs"
    );
    let motes = Store::open(root.join("motes"))?;
    let kernel = warden::vmm::boot::BootConfig::host_kernel()
        .ok_or_else(|| anyhow::anyhow!("host kernel required"))?;
    let kernel = motes.put(&fs::read(kernel)?)?;
    let initrd = motes.put(&fs::read(package.join("initramfs.cpio"))?)?;
    let toolfs = motes.put(&image)?;
    let closure = Store::open(root.join("closures"))?.put(&raw)?;
    let mote = motes.put(&serde_json::to_vec(&json!({"apiVersion":"celln.dev/v1alpha1","format":"celln.warm-closure-v1","kernel":kernel.0,"initrd":initrd.0,"toolfs":toolfs.0,"invocation":{"alias":signed.closure.entrypoint,"toolHash":runtime}}))?)?;
    let mut policy = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("trusted-motes.json"))?;
    policy.write_all(&serde_json::to_vec(
        &json!({"apiVersion":"celln.dev/v1alpha1","bundles":[mote.0]}),
    )?)?;
    policy.sync_all()?;
    println!(
        "{}",
        json!({"mote":{"hash":mote.0},"closure":{"hash":closure.0},"scope":"public test fixture only; no KVM or model execution; not readiness"})
    );
    Ok(())
}
