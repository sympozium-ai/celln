//! Public-seed catalogue packaging fixture. No model calls or readiness claims.
use anyhow::{ensure, Result};
use celln_manifest::{
    closure::{Closure, Member},
    Hash,
};
use celln_store::Store;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "usage: prepare_composition_fixture NEW_DIRECTORY EXISTING_JSON_PACKAGE"
    );
    let root = PathBuf::from(&args[1]);
    let package = PathBuf::from(&args[2]);
    fs::create_dir(&root)?;
    let descriptors = Store::open(root.join("closures"))?;
    let members = Store::open(root.join("tools"))?;
    let schemas = Store::open(root.join("tool-schemas"))?;
    let image = fs::read(package.join("toolfs.img"))?;
    let image_hash = Hash::of(&image);
    let mut sources = Vec::new();
    let mut tools = Vec::new();
    let mut runtime = None;
    let input=br#"{"type":"object","properties":{"text":{"type":"string","minLength":1,"maxLength":64}},"required":["text"],"additionalProperties":false}"#;
    let length=br#"{"type":"object","properties":{"length":{"type":"integer","minimum":0,"maximum":64}},"required":["length"],"additionalProperties":false}"#;
    let input_hash = schemas.put(input)?;
    let length_hash = schemas.put(length)?;
    for name in ["harness", "uppercase", "length"] {
        let hash = members.put(&fs::read(package.join(name))?)?;
        let mut graph = BTreeMap::from([(
            format!("/{name}"),
            Member {
                hash: hash.0.clone(),
                dependencies: BTreeSet::new(),
            },
        )]);
        if name == "harness" {
            let broker = members.put(&fs::read(package.join("pilot-fetch"))?)?;
            graph
                .get_mut("/harness")
                .unwrap()
                .dependencies
                .insert("/pilot-fetch".into());
            graph.insert(
                "/pilot-fetch".into(),
                Member {
                    hash: broker.0,
                    dependencies: BTreeSet::new(),
                },
            );
        }
        let signed = Closure {
            api_version: "celln.dev/closure-v1".into(),
            sources: vec![],
            toolfs: image_hash.0.clone(),
            entrypoint: format!("/{name}"),
            interpreter: false,
            members: graph,
        }
        .sign(&[42; 32])
        .map_err(anyhow::Error::msg)?;
        let identity = descriptors.put(&serde_json::to_vec(&signed)?)?;
        sources.push(identity.0.clone());
        if name == "harness" {
            runtime = Some(
                json!({"image":format!("example.invalid/packaging-only@sha256:{}","0".repeat(64)),"celln":{
    "revision":"v1","contractVersion":"celln.json-tools/v1","executable":{"hash":hash.0},"closure":{"hash":identity.0},
    "mote":{"hash":Hash::of(b"unprepared-mote-not-ready").0},"publisherKey":signed.publisher,"entryPoint":"/harness","platform":"linux/amd64","lane":"agent","lifecycle":"disposable-one-shot",
    "json":{"maxTurns":3,"maxCalls":2},"limits":{"timeoutMillis":180000,"memoryBytes":268435456,"taskBytes":2048,"outputBytes":65536,"workspace":"none"}}}),
            );
            fs::write(
                root.join("trusted-closures.json"),
                serde_json::to_vec(
                    &json!({"apiVersion":"celln.dev/closure-policy-v1","publishers":[signed.publisher],"revoked":[]}),
                )?,
            )?;
        } else {
            tools.push(json!({"name":name,"spec":{"revision":"v1","description":format!("Public JSON {name} fixture"),"supportOwner":"test","publisherKey":signed.publisher,
    "executable":{"hash":hash.0},"closure":{"hash":identity.0},"entryPoint":format!("/{name}"),"invocationABI":"celln.json-stdio/v1",
    "argumentsSchema":{"hash":input_hash.0},"resultSchema":{"hash":if name=="length"{&length_hash.0}else{&input_hash.0}},"platform":"linux/amd64","lane":"tool",
    "limits":{"timeoutMillis":1000,"memoryBytes":268435456,"argumentBytes":1024,"outputBytes":1024,"workspace":"none","effects":"none"}}}));
        }
    }
    fs::write(root.join("public-fixture-seed"), [42; 32])?;
    fs::write(
        root.join("catalogue.json"),
        serde_json::to_vec_pretty(
            &json!({"runtimeSpec":runtime,"tools":tools,"sources":sources,"scope":"real signed member bytes; packaging only; mote unprepared"}),
        )?,
    )?;
    println!("{}", root.display());
    Ok(())
}
