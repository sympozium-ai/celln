//! Public deterministic metadata-review fixture, NOT executable/conformance evidence.
use anyhow::{ensure, Result};
use celln_manifest::{
    closure::{Closure, Member},
    Hash,
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 2,
        "usage: prepare_review_fixture NEW_DIRECTORY"
    );
    let root = PathBuf::from(&args[1]);
    fs::create_dir(&root)?;
    let filesystem = b"non-executable review fixture; never mark Ready";
    let executable = Hash::of(b"declared example member").0;
    let signed = Closure {
        api_version: "celln.dev/closure-v1".into(),
        toolfs: Hash::of(filesystem).0,
        entrypoint: "/example".into(),
        interpreter: false,
        members: BTreeMap::from([(
            "/example".into(),
            Member {
                hash: executable.clone(),
                dependencies: BTreeSet::new(),
            },
        )]),
    }
    .sign(&[42; 32])
    .map_err(anyhow::Error::msg)?;
    let descriptor = serde_json::to_vec_pretty(&signed)?;
    let arguments = br#"{"type":"array","items":{"type":"string","minLength":0,"maxLength":64},"minItems":0,"maxItems":2}"#;
    let result = br#"{"type":"string","minLength":0,"maxLength":64}"#;
    for schema in [arguments.as_slice(), result.as_slice()] {
        celln_manifest::tool_schema::ToolSchema::parse(schema, &Hash::of(schema))
            .map_err(anyhow::Error::msg)?;
    }
    fs::write(root.join("closure.json"), &descriptor)?;
    fs::write(root.join("toolfs.ext2"), filesystem)?;
    fs::write(root.join("arguments.schema.json"), arguments)?;
    fs::write(root.join("result.schema.json"), result)?;
    fs::write(
        root.join("trusted-closures.json"),
        serde_json::to_vec(&json!({
            "apiVersion":"celln.dev/closure-policy-v1", "publishers":[signed.publisher], "revoked":[]
        }))?,
    )?;
    fs::write(
        root.join("submission.json"),
        serde_json::to_vec_pretty(&json!({
            "apiVersion":"sympozium.ai/v1alpha1", "kind":"CellnToolSubmission", "metadata":{"name":"review-fixture"},
            "spec": {"revision":"v1", "description":"Public non-executable review test; not conformance", "supportOwner":"test",
                "publisherKey":signed.publisher, "executable":{"hash":executable}, "closure":{"hash":Hash::of(&descriptor).0},
                "entryPoint":"/example", "invocationABI":"celln.argv/v1", "argumentsSchema":{"hash":Hash::of(arguments).0},
                "resultSchema":{"hash":Hash::of(result).0}, "platform":"linux/amd64", "lane":"tool",
                "limits":{"timeoutMillis":1000,"memoryBytes":33554432,"argumentBytes":1024,"outputBytes":1024,"workspace":"none","effects":"none"}
            }
        }))?,
    )?;
    println!("{}", root.display());
    Ok(())
}
