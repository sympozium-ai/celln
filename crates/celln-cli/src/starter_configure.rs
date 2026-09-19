//! Explicit operator grants for the first supported native starter profile.
//! No model credential bytes are read, printed or sent to Kubernetes.
use anyhow::{ensure, Context, Result};
use celln_manifest::Hash;
use celln_spec::{ConfigurationRole, ExecutionRequest};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Plan {
    api_version: String,
    package: PathBuf,
    package_hash: String,
    principal: String,
    credential_file: PathBuf,
    output: PathBuf,
    #[serde(default)]
    model_connection: Option<ModelConnection>,
    /// Operator ceilings for one parent: how long it may live and how much
    /// it may spend over its life. Absent fields keep the reviewed defaults.
    #[serde(default)]
    host_limits: Option<HostLimits>,
    /// Exact hosts the fetch and JSON POST tools may reach; the reviewed
    /// default is example.com. Lowercase DNS names, at most 16.
    #[serde(default)]
    https_hosts: Option<Vec<String>>,
}

fn resolve_hosts(hosts: Option<&Vec<String>>) -> Result<Vec<String>> {
    let hosts = hosts.cloned().unwrap_or_else(|| vec!["example.com".into()]);
    ensure!(
        !hosts.is_empty()
            && hosts.len() <= 16
            && hosts.iter().all(|host| {
                host.len() <= 253
                    && host.contains('.')
                    && host.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
            }),
        "httpsHosts must be 1..=16 lowercase DNS names"
    );
    Ok(hosts)
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostLimits {
    lease_seconds: Option<u64>,
    max_turns: Option<u64>,
    max_model_requests: Option<u64>,
    max_output_tokens: Option<u64>,
}

/// Per-turn allowance of the starter model profile; parent totals must afford
/// at least one such turn.
/// The worker template's model loop: `max_turns` model requests, of which all
/// but the last may carry tool calls, `max_calls` tool calls in total. Four
/// calls one at a time need five requests; six leaves one to recover.
const TEMPLATE_MAX_TURNS: u64 = 6;
const TEMPLATE_MAX_CALLS: u64 = 4;
/// Each model request may produce this many tokens (the broker's fixed cap).
const REQUEST_OUTPUT_TOKENS: u64 = 512;
// Every call needs a later request to hand its result to the model.
const _: () = assert!(TEMPLATE_MAX_CALLS < TEMPLATE_MAX_TURNS);
const TURN_MODEL_REQUESTS: u64 = TEMPLATE_MAX_TURNS;
const TURN_OUTPUT_TOKENS: u64 = TEMPLATE_MAX_TURNS * REQUEST_OUTPUT_TOKENS;
/// Turns a parent may take when the operator states no ceilings.
const DEFAULT_MAX_TURNS: u64 = 12;

struct ResolvedLimits {
    lease_seconds: u64,
    max_turns: u64,
    max_model_requests: u64,
    max_output_tokens: u64,
}

fn resolve_limits(limits: Option<&HostLimits>) -> Result<ResolvedLimits> {
    let limits = limits.cloned().unwrap_or_default();
    let resolved = ResolvedLimits {
        lease_seconds: limits.lease_seconds.unwrap_or(3600),
        max_turns: limits.max_turns.unwrap_or(DEFAULT_MAX_TURNS),
        max_model_requests: limits
            .max_model_requests
            .unwrap_or(DEFAULT_MAX_TURNS * TURN_MODEL_REQUESTS),
        max_output_tokens: limits
            .max_output_tokens
            .unwrap_or(DEFAULT_MAX_TURNS * TURN_OUTPUT_TOKENS),
    };
    ensure!(
        (60..=86_400).contains(&resolved.lease_seconds)
            && (1..=1024).contains(&resolved.max_turns)
            && (TURN_MODEL_REQUESTS..=6144).contains(&resolved.max_model_requests)
            && (TURN_OUTPUT_TOKENS..=3_145_728).contains(&resolved.max_output_tokens),
        "host limits out of range: leaseSeconds 60..=86400, maxTurns 1..=1024, maxModelRequests 6..=6144, maxOutputTokens 3072..=3145728"
    );
    Ok(resolved)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelConnection {
    provider: String,
    protocol: warden::egress::ModelProtocol,
    endpoint: String,
    model: String,
    credential_profile: String,
    #[serde(default)]
    allow_insecure: bool,
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

pub fn run(plan: &Path, root: &Path) -> Result<u8> {
    let plan: Plan = serde_json::from_slice(&crate::starter_package::regular(plan, 16384)?)?;
    let connection = plan.model_connection.as_ref();
    let endpoint = connection.map_or("https://api.deepseek.com/chat/completions", |c| {
        c.endpoint.as_str()
    });
    let model = connection.map_or("deepseek-chat", |c| c.model.as_str());
    warden::egress::model_endpoint_target(endpoint, connection.is_some_and(|c| c.allow_insecure))
        .map_err(anyhow::Error::msg)?;
    if let Some(c) = connection {
        let identifier = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        };
        ensure!(
            identifier(&c.provider)
                && identifier(&c.credential_profile)
                && !model.is_empty()
                && model.len() <= 128
                && model.trim() == model
                && !model.chars().any(char::is_control),
            "invalid model connection"
        );
    }
    ensure!(
        plan.api_version == "celln.native-starter-config/v1",
        "unsupported starter configuration"
    );
    ensure!(
        !plan.principal.is_empty()
            && plan.principal.len() <= 128
            && !plan.principal.chars().any(char::is_control),
        "bounded principal required"
    );
    ensure!(
        root.is_absolute() && plan.output.is_absolute() && !plan.output.try_exists()?,
        "existing authority and new absolute output required"
    );
    ensure!(
        plan.credential_file.is_absolute()
            && !plan
                .credential_file
                .starts_with(root.parent().context("state parent required")?)
            && !plan
                .credential_file
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "model credential path must be absolute and outside controller-mounted state"
    );
    crate::starter_admit::verified(&plan.package, &plan.package_hash, root)?;
    let raw = crate::starter_package::regular(&plan.package.join("package.json"), 65536)?;
    ensure!(
        Hash::of(&raw).0 == plan.package_hash,
        "package changed during configuration"
    );
    let package: Value = serde_json::from_slice(&raw)?;
    let entries = package["bundles"].as_array().context("bundles required")?;
    let policy: Value = serde_json::from_slice(&crate::starter_package::regular(
        &root.join("trusted-motes.json"),
        1 << 20,
    )?)?;
    let admitted = policy["bundles"]
        .as_array()
        .context("host mote policy required")?;
    ensure!(
        entries
            .iter()
            .all(|entry| admitted.contains(&entry["mote"])),
        "every native starter mote must be independently admitted first"
    );
    let entry = |name: &str| entries.iter().find(|entry| entry["name"] == name).unwrap();
    let request = |name: &str, timeout: u64| -> Result<ExecutionRequest> {
        let bundle = entry(name);
        Ok(serde_json::from_value(
            json!({"apiVersion":"celln.dev/v1alpha1","id":format!("native-{name}"),"workload":{"id":format!("native-{name}"),"caller":plan.principal},"mote":{"hash":bundle["mote"]},"tools":[{"alias":bundle["entryPoint"],"hash":bundle["executable"],"closure":{"hash":bundle["closure"]}}],"invocation":{"alias":bundle["entryPoint"],"args":[]},"capabilities":{"workspace":"none","timeoutMs":timeout,"memoryBytes":268435456u64,"outputBytes":65536},"execution":{"lane":"agent","requireHardwareIsolation":true}}),
        )?)
    };
    let limits = resolve_limits(plan.host_limits.as_ref())?;
    let hosts = resolve_hosts(plan.https_hosts.as_ref())?;
    let parent = request("parent", limits.lease_seconds * 1000)?;
    let worker = request("worker", 60000)?;
    let error = json!({"type":"string","minLength":1,"maxLength":1024});
    let revision = json!({"type":"integer","minimum":0,"maximum":65536});
    let name = json!({"type":"string","minLength":1,"maxLength":256});
    let content = json!({"type":"string","minLength":0,"maxLength":4096});
    let output_schema = json!({"type":"object","properties":{"revision":revision,"content":content,"error":error},"required":[],"additionalProperties":false}).to_string();
    let list_output = json!({"type":"object","properties":{"revision":revision,"files":{"type":"array","minItems":0,"maxItems":64,"items":{"type":"object","properties":{"name":name,"bytes":{"type":"integer","minimum":0,"maximum":1048576}},"required":["name","bytes"],"additionalProperties":false}},"error":error},"required":[],"additionalProperties":false}).to_string();
    let search_output = json!({"type":"object","properties":{"revision":revision,"matches":{"type":"array","minItems":0,"maxItems":32,"items":{"type":"object","properties":{"name":name,"line":{"type":"integer","minimum":1,"maximum":1048576},"text":{"type":"string","minLength":0,"maxLength":256}},"required":["name","line","text"],"additionalProperties":false}},"error":error},"required":[],"additionalProperties":false}).to_string();
    let post_output = json!({"type":"object","properties":{"status":{"type":"integer","minimum":100,"maximum":599},"content":content,"error":error},"required":[],"additionalProperties":false}).to_string();
    // Descriptions are what the model reads; names alone leave it guessing
    // which revision to pass or what a search returns.
    let specifications = [
        (
            "workspace-read",
            "Read a run file by name; returns its content and the workspace revision.",
            json!({"type":"object","properties":{"name":name},"required":["name"],"additionalProperties":false}),
            output_schema.clone(),
        ),
        (
            "workspace-write",
            "Replace or create a run file at the given workspace revision (0 for an empty workspace).",
            json!({"type":"object","properties":{"name":name,"revision":revision,"content":content},"required":["name","revision","content"],"additionalProperties":false}),
            output_schema.clone(),
        ),
        (
            "https-fetch",
            "GET an HTTPS URL on an allowed host; returns the body as text.",
            json!({"type":"object","properties":{"url":{"type":"string","minLength":1,"maxLength":2048}},"required":["url"],"additionalProperties":false}),
            output_schema.clone(),
        ),
        (
            "workspace-list",
            "List every run file with its size and the workspace revision.",
            json!({"type":"object","properties":{},"required":[],"additionalProperties":false}),
            list_output,
        ),
        (
            "workspace-append",
            "Append text to a run file (created if absent) at the given workspace revision.",
            json!({"type":"object","properties":{"name":name,"revision":revision,"content":content},"required":["name","revision","content"],"additionalProperties":false}),
            output_schema.clone(),
        ),
        (
            "workspace-search",
            "Find lines of run files containing an exact substring; returns file, line number and text.",
            json!({"type":"object","properties":{"pattern":{"type":"string","minLength":1,"maxLength":256}},"required":["pattern"],"additionalProperties":false}),
            search_output,
        ),
        (
            "workspace-delete",
            "Delete a run file at the given workspace revision.",
            json!({"type":"object","properties":{"name":name,"revision":revision},"required":["name","revision"],"additionalProperties":false}),
            output_schema.clone(),
        ),
        (
            "https-post-json",
            "POST a JSON object (given as text) to an HTTPS URL on an allowed host; returns the status and body.",
            json!({"type":"object","properties":{"url":{"type":"string","minLength":1,"maxLength":2048},"body":{"type":"string","minLength":2,"maxLength":4096}},"required":["url","body"],"additionalProperties":false}),
            post_output,
        ),
    ];
    let schema = |bytes: String| json!({"hash":Hash::of(bytes.as_bytes()),"bytes":bytes});
    let mut tools: Vec<_> = specifications.iter().map(|(name,description,input,output)| json!({"name":name,"path":format!("/{name}"),"hash":entry(name)["executable"],"description":description,"input_schema":schema(input.to_string()),"output_schema":schema(output.clone()),"input_bytes":8192,"output_bytes":32768,"timeout_ms":30000})).collect();
    // Commands borrowed from pinned images at packaging time: each is an argv
    // tool whose executable the package already hashes under `programs`.
    let commands: Vec<crate::starter_package::PackagedCommand> = match package.get("commands") {
        Some(value) => serde_json::from_value(value.clone())?,
        None => Vec::new(),
    };
    let programs = package["programs"]
        .as_object()
        .context("programs required")?;
    for packaged in &commands {
        crate::tool_commands::validate(&packaged.command)?;
        let hash = programs
            .get(&packaged.alias)
            .and_then(Value::as_str)
            .with_context(|| format!("package lacks program {}", packaged.alias))?;
        let input = crate::tool_commands::input_schema(&packaged.command).to_string();
        let output = pilot::json_harness::argv_output_schema().to_string();
        let description = crate::tool_commands::description_with_params(&packaged.command);
        tools.push(json!({"name":packaged.command.name,"path":packaged.alias,"hash":hash,"description":description,"input_schema":schema(input),"output_schema":schema(output),"input_bytes":8192,"output_bytes":8192,"timeout_ms":30000,"argv":{"args":packaged.command.args,"stdin":packaged.command.stdin}}));
    }
    ensure!(tools.len() <= 24, "at most 24 borrowed tools per worker");
    let mut template_json = json!({"contract":"celln.json-tools/v1","task":"","system":"Use the borrowed tools when requested. Read files with workspace-read rather than relying on remembered content. Keep replies brief.","url":endpoint,"model":model,"tools":tools,"max_turns":TEMPLATE_MAX_TURNS,"max_calls":TEMPLATE_MAX_CALLS,"require_tool_call":false});
    if connection.is_some_and(|c| c.allow_insecure) {
        template_json["allow_insecure"] = json!(true);
    }
    let template = pilot::turn_worker::Template::new(serde_json::from_value(template_json)?)?;
    let profile = serde_json::to_vec(
        &json!({"apiVersion":"celln.parent-model-profile/v1","protocol":connection.map(|c| c.protocol).unwrap_or_default(),"allowInsecure":connection.is_some_and(|c| c.allow_insecure),"principal":plan.principal,"requestBinding":worker.configuration_binding(ConfigurationRole::Worker).map_err(anyhow::Error::msg)?,"templateBinding":template.binding(),"credentialFile":plan.credential_file,"url":template.policy().url,"model":template.policy().model,"maxRequests":TURN_MODEL_REQUESTS,"maxOutputTokens":REQUEST_OUTPUT_TOKENS,"maxTotalOutputTokens":TURN_OUTPUT_TOKENS,"workspace":{"read":true,"write":true,"maxOperations":8,"maxFiles":8,"maxFileBytes":4096,"maxTotalBytes":16384},"fetch":{"allowHosts":hosts,"maxRequests":4,"maxResponseBytes":4096,"timeoutMs":10000},"post":{"allowHosts":hosts,"maxRequests":4,"maxBodyBytes":4096,"maxResponseBytes":4096,"timeoutMs":10000}}),
    )?;
    let profile_hash = Hash::of(&profile);
    let mut catalogue_tools = Vec::new();
    for tool in &template.policy().tools {
        if let Some(packaged) = commands.iter().find(|c| c.command.name == tool.name) {
            // A borrowed command: no broker effects, provenance is the image.
            let limits = json!({"timeoutMillis":30000,"memoryBytes":268435456u64,"argumentBytes":8192,"outputBytes":32768,"workspace":"none","effects":"none"});
            let worker = entry("worker");
            catalogue_tools.push(json!({"name":tool.name,"spec":{"revision":"v1","description":tool.description,"supportOwner":"native-starter-operator","publisherKey":worker["publisher"],"executable":{"hash":tool.hash},"closure":{"hash":worker["closure"]},"entryPoint":tool.path,"invocationABI":"celln.argv/v1","argumentsSchema":{"hash":tool.input_schema.hash},"resultSchema":{"hash":tool.output_schema.hash},"platform":"linux/amd64","lane":"tool","sourceImage":packaged.source_image,"limits":limits}}));
            continue;
        }
        let bundle = entry(&tool.name);
        let mut limits = json!({"timeoutMillis":30000,"memoryBytes":268435456u64,"argumentBytes":8192,"outputBytes":32768,"workspace":"none","effects":"none"});
        if tool.name == "https-fetch" || tool.name == "https-post-json" {
            limits["effects"] = json!("external-side-effects");
            limits["https"] = json!({"allowHosts":hosts,"maxRequests":4,"maxResponseBytes":4096,"timeoutMillis":10000});
        } else {
            // The operation names what the broker will do; changing run data
            // is an effect the operator approves, reading is not.
            let operation = tool.name.strip_prefix("workspace-").unwrap_or(&tool.name);
            if matches!(operation, "write" | "append" | "delete") {
                limits["effects"] = json!("external-side-effects");
            }
            limits["artifacts"] = json!({"operation":operation,"maxOperations":8,"maxFiles":8,"maxFileBytes":4096,"maxTotalBytes":16384});
        }
        catalogue_tools.push(json!({"name":tool.name,"spec":{"revision":"v1","description":tool.description,"supportOwner":"native-starter-operator","publisherKey":bundle["publisher"],"executable":{"hash":bundle["executable"]},"closure":{"hash":bundle["closure"]},"entryPoint":tool.path,"invocationABI":"celln.json-stdio/v1","argumentsSchema":{"hash":tool.input_schema.hash},"resultSchema":{"hash":tool.output_schema.hash},"platform":"linux/amd64","lane":"tool","limits":limits}}));
    }
    let bundle = entry("worker");
    let catalogue = json!({"systemPrompt":template.policy().system,"tools":catalogue_tools,"worker":{"revision":"v1","contractVersion":"celln.json-tools/v1","publisherKey":bundle["publisher"],"executable":{"hash":bundle["executable"]},"closure":{"hash":bundle["closure"]},"mote":{"hash":bundle["mote"]},"entryPoint":"/worker","platform":"linux/amd64","lane":"agent","lifecycle":"disposable-one-shot","json":{"maxTurns":TEMPLATE_MAX_TURNS,"maxCalls":TEMPLATE_MAX_CALLS},"limits":{"timeoutMillis":60000,"memoryBytes":268435456u64,"taskBytes":warden::parent_protocol::MAX_TASK_BYTES,"outputBytes":65536,"workspace":"none"}}});
    let native = json!({"admissionWindowMs":120000,"parent":parent,"worker":worker,"template":template.policy(),"modelProfile":profile_hash,"reservedMemoryBytes":1342177280u64,"maxTurns":limits.max_turns,"turnModelRequests":TURN_MODEL_REQUESTS,"turnOutputTokens":TURN_OUTPUT_TOKENS,"totalModelRequests":limits.max_model_requests,"totalOutputTokens":limits.max_output_tokens});
    let catalogue_bytes = serde_json::to_vec_pretty(&catalogue)?;
    let native_bytes = serde_json::to_vec_pretty(&native)?;
    fs::DirBuilder::new().mode(0o700).create(&plan.output)?;
    write_new(&plan.output.join("catalogue.json"), &catalogue_bytes)?;
    write_new(&plan.output.join("native-template.json"), &native_bytes)?;
    let profiles = root.join("trusted-parent-models");
    fs::create_dir_all(&profiles)?;
    let path = profiles.join(format!("{}.json", &profile_hash.0[7..]));
    if path.try_exists()? {
        ensure!(
            crate::starter_package::regular(&path, 65536)? == profile,
            "existing model profile differs"
        );
    } else {
        write_new(&path, &profile)?;
    }
    fs::File::open(profiles)?.sync_all()?;
    let mut complete = json!({"apiVersion":"celln.native-starter-configured/v1","packageHash":plan.package_hash,"catalogueHash":Hash::of(&catalogue_bytes),"nativeTemplateHash":Hash::of(&native_bytes),"principal":plan.principal,"modelProfile":profile_hash,"model":{"provider":"deepseek","model":"deepseek-chat"},"hostLimits":{"leaseSeconds":limits.lease_seconds,"maxTurns":limits.max_turns,"maxModelRequests":limits.max_model_requests,"maxOutputTokens":limits.max_output_tokens},"httpsHosts":hosts,"executionAuthorized":false,"readiness":"not_established"});
    if let Some(c) = connection {
        complete["model"] = json!({"provider":c.provider,"protocol":c.protocol,"model":c.model,"baseURL":c.endpoint,"credentialProfile":c.credential_profile,"allowInsecure":c.allow_insecure});
    }
    write_new(
        &plan.output.join("configured.json"),
        &serde_json::to_vec_pretty(&complete)?,
    )?;
    fs::File::open(&plan.output)?.sync_all()?;
    println!("{}", complete);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_turn_affords_the_template_loop_and_totals_afford_every_turn() {
        // Four tool calls made one at a time take five model requests.
        assert_eq!((TEMPLATE_MAX_TURNS, TEMPLATE_MAX_CALLS), (6, 4));
        assert_eq!((TURN_MODEL_REQUESTS, TURN_OUTPUT_TOKENS), (6, 3072));
        let defaults = resolve_limits(None).unwrap();
        assert_eq!(
            (
                defaults.max_turns,
                defaults.max_model_requests,
                defaults.max_output_tokens
            ),
            (12, 72, 36864)
        );
        // Totals that cannot pay for one turn are refused, not starved later.
        let limits = |requests, tokens| HostLimits {
            max_model_requests: Some(requests),
            max_output_tokens: Some(tokens),
            ..Default::default()
        };
        assert!(resolve_limits(Some(&limits(6, 3072))).is_ok());
        assert!(resolve_limits(Some(&limits(5, 3072))).is_err());
        assert!(resolve_limits(Some(&limits(6, 3071))).is_err());
        assert!(resolve_limits(Some(&limits(6144, 3_145_728))).is_ok());
    }
}
