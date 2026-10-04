//! Builds the exact runtime + two explicitly lent artifact tool composition.
use super::*;

pub(super) fn artifact_fixture(
    root: &Path,
    runtime: &Path,
    kernel: &Path,
    binaries: &Path,
    report: &serde_json::Value,
) -> (ExecutionRequest, serde_json::Value) {
    let mut worker = bundle(
        root,
        runtime,
        kernel,
        "artifact-worker",
        &[
            ("/worker", binaries.join("celln-harness-turn")),
            ("/pilot-fetch", binaries.join("pilot-fetch")),
            ("/workspace-read", binaries.join("celln-workspace-read")),
            ("/workspace-write", binaries.join("celln-workspace-write")),
        ],
    );
    let descriptors = Store::open(root.join("closures")).unwrap();
    let old: celln_manifest::closure::SignedClosure = serde_json::from_slice(
        &descriptors
            .get(&Hash(
                worker.tools[0].closure.as_ref().unwrap().hash.clone(),
            ))
            .unwrap(),
    )
    .unwrap();
    let entry = |name: &str| {
        report["bundles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .unwrap()
    };
    let sources = ["runtime", "workspace-read", "workspace-write"]
        .into_iter()
        .map(|name| {
            let hash = entry(name)["closure"].as_str().unwrap().to_owned();
            celln_manifest::closure::composition::Source {
                descriptor: String::from_utf8(descriptors.get(&Hash(hash.clone())).unwrap())
                    .unwrap(),
                hash,
            }
        })
        .collect();
    let composed =
        celln_manifest::closure::composition::compose(sources, &Hash(old.closure.toolfs))
            .unwrap()
            .sign(&[31; 32])
            .unwrap();
    worker.tools[0].closure.as_mut().unwrap().hash = descriptors
        .put(&serde_json::to_vec(&composed).unwrap())
        .unwrap()
        .0;
    let schemas = Store::open(root.join("tool-schemas")).unwrap();
    let name = json!({"type":"string","minLength":1,"maxLength":256});
    let revision = json!({"type":"integer","minimum":0,"maximum":65536});
    let content = json!({"type":"string","minLength":0,"maxLength":4096});
    let output = json!({"type":"object","properties":{"revision":revision,"content":content,"error":{"type":"string","minLength":1,"maxLength":1024}},"required":[],"additionalProperties":false});
    let output_hash = schemas.put(&serde_json::to_vec(&output).unwrap()).unwrap();
    let mut tools = Vec::new();
    for operation in ["read", "write"] {
        let tool = format!("workspace-{operation}");
        let bundle = entry(&tool);
        let input = if operation == "read" {
            json!({"type":"object","properties":{"name":name},"required":["name"],"additionalProperties":false})
        } else {
            json!({"type":"object","properties":{"name":name,"revision":revision,"content":content},"required":["name","revision","content"],"additionalProperties":false})
        };
        let input_hash = schemas.put(&serde_json::to_vec(&input).unwrap()).unwrap();
        tools.push(json!({"name":tool,"uid":format!("fixture-{tool}"),"spec":{
            "revision":"v1","description":format!("{operation} run artifact"),"supportOwner":"fixture",
            "publisherKey":bundle["publisher"],"executable":{"hash":bundle["executable"]},"closure":{"hash":bundle["closure"]},
            "entryPoint":format!("/{tool}"),"invocationABI":"celln.json-stdio/v1","argumentsSchema":{"hash":input_hash},"resultSchema":{"hash":output_hash},
            "platform":"linux/amd64","lane":"tool","limits":{"timeoutMillis":30000,"memoryBytes":268435456,"argumentBytes":8192,"outputBytes":32768,"workspace":"none",
                "effects":if operation == "write" {"external-side-effects"} else {"none"},
                "artifacts":{"operation":operation,"maxOperations":4,"maxFiles":8,"maxFileBytes":4096,"maxTotalBytes":16384}}
        }}));
    }
    (worker, serde_json::Value::Array(tools))
}
