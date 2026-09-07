//! Operator-owned fixture preparation for the deployed reference Harness proof.
//! No model calls, credentials, or cluster mutations. Not a user admission API.
#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{ensure, Context, Result};
    use celln_manifest::{closure::SignedClosure, Hash};
    use celln_spec::ExecutionRequest;
    use celln_store::Store;
    use serde_json::json;
    use std::{fs, path::PathBuf};

    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args().collect();
        ensure!(
            args.len() == 4,
            "usage: prepare_harness_fixture PACKAGE NEW_STATE_DIR CALLER"
        );
        let package = PathBuf::from(&args[1]);
        let root = PathBuf::from(&args[2]);
        fs::create_dir(&root).context("state directory must not already exist")?;
        let motes = Store::open(root.join("motes"))?;
        let tools = Store::open(root.join("tools"))?;
        let runtime = tools.put(&fs::read(package.join("harness"))?)?;
        let signed_bytes = fs::read(package.join("signed-closure.json"))?;
        let signed: SignedClosure = serde_json::from_slice(&signed_bytes)?;
        signed
            .verify(&[signed.publisher.clone()].into_iter().collect())
            .map_err(anyhow::Error::msg)?;
        let closure = Store::open(root.join("closures"))?.put(&signed_bytes)?;
        fs::write(
            root.join("trusted-closures.json"),
            serde_json::to_vec(&json!({
                "apiVersion":"celln.dev/closure-policy-v1", "publishers":[signed.publisher], "revoked":[]
            }))?,
        )?;
        let kernel = warden::vmm::boot::BootConfig::host_kernel()
            .context("readable host kernel required")?;
        let kernel = motes.put(&fs::read(kernel)?)?;
        let initrd = motes.put(&fs::read(package.join("initramfs.cpio"))?)?;
        let toolfs = motes.put(&fs::read(package.join("toolfs.img"))?)?;
        ensure!(signed.closure.toolfs == toolfs.0, "closure/toolfs mismatch");
        let mote = motes.put(&serde_json::to_vec(&json!({
            "apiVersion":"celln.dev/v1alpha1", "format":"celln.warm-closure-v1",
            "kernel":kernel.0, "initrd":initrd.0, "toolfs":toolfs.0,
            "invocation":{"alias":"/harness", "toolHash":runtime.0}
        }))?)?;
        fs::write(
            root.join("trusted-motes.json"),
            serde_json::to_vec(&json!({
                "apiVersion":"celln.dev/v1alpha1", "bundles":[mote.0]
            }))?,
        )?;
        let borrowed = json!([
            {"name":"add","path":"/add","hash":signed.closure.members["/add"].hash,"description":"Add two integer strings."},
            {"name":"multiply","path":"/multiply","hash":signed.closure.members["/multiply"].hash,"description":"Multiply two integer strings."}
        ]);
        // Only the path is part of the grant. Operator supplies a Secret mount at
        // deployment time; no token bytes are read or packaged by this program.
        let grant = serde_json::to_vec(&json!({
            "apiVersion":"celln.dev/harness-grant-v1", "caller":args[3],
            "mote":mote.0,"runtime":runtime.0,"closure":closure.0,"borrowedTools":borrowed,
            "url":"https://api.deepseek.com/chat/completions", "model":"deepseek-chat",
            "credentialFile":"/etc/celln/model/token", "maxRequests":3,
            "maxOutputTokens":512,"maxTotalOutputTokens":1536
        }))?;
        let grant_hash = Hash::of(&grant);
        fs::create_dir(root.join("trusted-harness"))?;
        fs::write(
            root.join("trusted-harness").join(format!(
                "{}.json",
                grant_hash.0.trim_start_matches("blake3:")
            )),
            grant,
        )?;
        let request: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion":"celln.dev/v1alpha2", "id":"harness-deployed-proof",
            "workload":{"id":"harness-deployed-proof", "caller":args[3]},
            "mote":{"hash":mote.0},
            "tools":[{"alias":"/harness","hash":runtime.0,"closure":{"hash":closure.0}}],
            "invocation":{"alias":"/harness"},
            "harness":{"model":"deepseek-chat","contractVersion":"celln.reference-functions/v1",
              "modelGrant":{"hash":grant_hash.0},"borrowedTools":borrowed,
              "task":"Use add with args [\"37\",\"5\"], wait for its result, then multiply that result by \"2\". Reply with exactly the final integer."},
            "capabilities":{"workspace":"none","egress":["https://api.deepseek.com"],
              "timeoutMs":180000,"memoryBytes":268435456,"outputBytes":65536},
            "execution":{"lane":"agent","requireHardwareIsolation":true}
        }))?;
        ensure!(
            request.problems().is_empty(),
            "invalid request: {:?}",
            request.problems()
        );
        fs::write(
            root.join("request.json"),
            serde_json::to_vec_pretty(&request)?,
        )?;
        println!(
            "Prepared operator fixture at {}; no credential or model call",
            root.display()
        );
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Unsupported: deployed KVM fixture preparation requires Linux")
    }
}
