//! One-shot, verified Celln dispatch.
//!
//! This is deliberately a native Celln execution path, not a Kubernetes Job
//! wrapper. Kubernetes may transport the request later; this module resolves
//! the declared immutable bundle, creates the cell, and returns a receipt.

use celln_manifest::Hash;
use celln_spec::{ExecutionRequest, ForgeRequest, RequestedLane};
use celln_store::Store;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[path = "dispatch_closure.rs"]
pub(crate) mod closure;
#[path = "dispatch_harness.rs"]
pub(crate) mod harness;

#[path = "dispatch_substrate.rs"]
mod substrate;
pub(crate) use substrate::check_members;
pub(crate) use substrate::launch_declared;
#[path = "dispatch_inputs.rs"]
pub(crate) mod inputs;
#[cfg(target_os = "linux")]
#[path = "dispatch_warm.rs"]
pub(crate) mod warm;

/// The serializable substrate descriptor stored under `ExecutionRequest.mote`.
/// Each referenced object is resolved by content hash before the VMM is given
/// any bytes. The in-guest pilot remains responsible for confirming that the
/// selected program hash is executable from the sealed tool filesystem.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MoteBundle {
    #[serde(rename = "apiVersion")]
    api_version: String,
    #[serde(default)]
    format: Option<String>,
    kernel: String,
    initrd: String,
    toolfs: String,
    invocation: BundleInvocation,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BundleInvocation {
    alias: String,
    tool_hash: String,
}

/// Fully resolved bytes/identities the runtime can hand to its KVM launcher.
/// This boundary makes store reads observable and prevents node admission from
/// being mistaken for artifact resolution.
#[derive(Debug, Serialize)]
pub struct ResolvedBundle {
    pub bundle_hash: String,
    pub program_hash: String,
    pub kernel_hash: String,
    pub initrd_hash: String,
    pub toolfs_hash: String,
    #[serde(skip)]
    kernel_bytes: Vec<u8>,
    #[serde(skip)]
    initrd_bytes: Vec<u8>,
    #[serde(skip)]
    toolfs_bytes: Vec<u8>,
    #[serde(skip)]
    format: Option<String>,
}

/// Runtime support is narrower than the transport schema. Do not silently
/// discard requested authority or describe requested-but-unused objects as
/// resolved provenance. Remove each refusal only with its delivery proof.
pub(crate) fn check_supported_authority(request: &ExecutionRequest) -> Result<(), String> {
    celln_control::check().map_err(|e| e.to_string())?;
    inputs::validate(request)?;
    if request.harness.is_some() {
        if !request.problems().is_empty() {
            return Err("invalid Harness binding".into());
        }
        return Ok(());
    }
    if request.tools.iter().any(|tool| tool.closure.is_some())
        && (request.forge.is_some()
            || !request.inputs.is_empty()
            || !request.capabilities.egress.is_empty())
    {
        return Err("unsupported authority: closure delivery with forge, inputs or egress".into());
    }
    if request.tools.len() > 1 {
        return Err("unsupported authority: only the invoked tool can be delivered".into());
    }
    Ok(())
}

pub fn resolve_bundle(
    request: &ExecutionRequest,
    mote_root: &Path,
    tool_root: &Path,
) -> Result<ResolvedBundle, String> {
    // `admit` already runs this for the HTTP dispatcher's own submit path, but
    // `celln node resolve-file` calls this function directly on a request that
    // was never admitted (deliberately — resolution and admission are separate
    // commands). Without this check here, a malformed hash in the request
    // (e.g. one containing a path-traversal segment) would flow straight into
    // `Store::get` below relying solely on the store's own defenses.
    let problems = request.problems();
    if !problems.is_empty() {
        return Err(format!(
            "execution request is invalid ({} problem(s)): {}",
            problems.len(),
            problems
                .iter()
                .map(|p| format!("{}: {}", p.field, p.message))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    check_supported_authority(request)?;
    let mote = request
        .mote
        .as_ref()
        .ok_or_else(|| "dispatch requires a declared mote".to_owned())?;
    let invocation = request
        .invocation
        .as_ref()
        .ok_or_else(|| "dispatch requires invocation".to_owned())?;
    let mote_hash = Hash(mote.hash.clone());
    let mote_store = Store::open(mote_root).map_err(|error| error.to_string())?;
    let bytes = mote_store
        .get(&mote_hash)
        .map_err(|error| error.to_string())?;
    let bundle: MoteBundle = serde_json::from_slice(&bytes)
        .map_err(|error| format!("mote bundle is not valid JSON: {error}"))?;
    if bundle.api_version != "celln.dev/v1alpha1" {
        return Err("mote bundle has an unsupported apiVersion".to_owned());
    }
    if bundle.invocation.alias != invocation.alias {
        return Err("mote bundle invocation alias does not match request".to_owned());
    }
    let requested_tool = request
        .tools
        .iter()
        .find(|tool| tool.alias == invocation.alias)
        .ok_or_else(|| "request invocation is not a declared tool".to_owned())?;
    if requested_tool.hash != bundle.invocation.tool_hash {
        return Err("mote bundle program hash does not match request".to_owned());
    }
    let tool_store = Store::open(tool_root).map_err(|error| error.to_string())?;
    tool_store
        .get(&Hash(requested_tool.hash.clone()))
        .map_err(|error| format!("declared program cannot be resolved: {error}"))?;
    let read_object = |hash: &str| {
        mote_store
            .get(&Hash(hash.to_owned()))
            .map_err(|error| format!("mote bundle object cannot be resolved: {error}"))
    };

    Ok(ResolvedBundle {
        format: bundle.format,
        kernel_bytes: read_object(&bundle.kernel)?,
        initrd_bytes: read_object(&bundle.initrd)?,
        toolfs_bytes: read_object(&bundle.toolfs)?,
        bundle_hash: mote.hash.clone(),
        program_hash: requested_tool.hash.clone(),
        kernel_hash: bundle.kernel,
        initrd_hash: bundle.initrd,
        toolfs_hash: bundle.toolfs,
    })
}

/// What actually happened inside the cell, once it dissolved.
///
/// This is deliberately not the [`celln_spec::ExecutionReceipt`] itself: the
/// receipt is an immutable, versioned wire contract with no room for a human
/// diagnostic, and a caller polling a pending execution needs a place to put
/// one. The dispatcher builds the receipt from this after the cell is gone.
#[derive(Debug)]
pub struct LaunchOutcome {
    pub execution: Option<pilot::dispatch_report::ExecutionGrant>,
    pub substrate: Option<SubstrateIdentity>,
    pub broker: BrokerActivity,
    pub lifecycle: Vec<CellEvent>,
    /// Verified inputs acknowledged as staged by pilot, not just requested.
    pub input_hashes: Vec<String>,
    pub cell_id: String,
    /// Bounded workload bytes, including failure output; may be empty.
    pub output: Option<Vec<u8>>,
    /// A refusal, nonzero exit, signal, timeout or protocol failure reason.
    pub denial: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubstrateIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closure: Option<closure::Provenance>,
    pub kernel: String,
    /// Exact loaded initrd including the fixed warm-dispatch marker.
    pub initrd: String,
    pub toolfs: String,
    pub invocation: String,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerActivity {
    pub requests: u64,
    pub denied: u64,
    pub response_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CellEvent {
    pub phase: String,
    pub at: String,
    #[serde(skip)]
    pub observed: std::time::Instant,
}

impl LaunchOutcome {
    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0)
            && self.signal.is_none()
            && !self.timed_out
            && self.denial.is_none()
    }
}

#[path = "dispatch_outcome.rs"]
mod outcome;
use outcome::parse_report;

/// What `forge` produced: the exact bytes now admitted into this node's
/// attested manifest, and their content hash.
pub struct ForgedProgram {
    pub hash: String,
    pub bytes: Vec<u8>,
}

/// Ask a model to write the requested task, build it twice in different
/// directories and compare the bytes (the same reproducibility check `celln
/// agent` runs), and admit whatever came back — real bytes, real hash,
/// `author=agent` — into this node's attested manifest.
///
/// The task string itself is never executable authority. It only becomes
/// one after this function has already run: the hash `launch` seals is a
/// hash of bytes that exist, not a description of intent. This is the same
/// authority model `celln agent` already uses on the CLI; this function is
/// that same sequence, callable from a request instead of a terminal.
#[cfg(target_os = "linux")]
pub fn forge(
    forge_request: &ForgeRequest,
    assay_root: &Path,
    timeout_secs: u64,
) -> Result<ForgedProgram, String> {
    use crate::agent::{ask_model, discover_backend, Backend, ALIAS, AVAILABLE_RUNTIMES, BRIEF};
    celln_control::check().map_err(|e| e.to_string())?;

    let backend = match forge_request.backend.as_deref() {
        Some(name) => Backend::from_saved_name(name).ok_or_else(|| {
            format!("forge.backend {name:?} is not one of: anthropic, openai, deepseek, local")
        })?,
        None => discover_backend().ok_or_else(|| {
            "no agent CLI found on this host — install and authenticate codex, claude, \
             or ollama, then run `celln setup`"
                .to_owned()
        })?,
    };
    if !backend.available() {
        return Err(format!(
            "{} needs `{}` on PATH",
            backend.label(),
            backend.program()
        ));
    }
    let model = forge_request
        .model
        .as_deref()
        .or_else(|| backend.default_model());

    let runtimes = AVAILABLE_RUNTIMES
        .iter()
        .map(|runtime| format!("- {}", runtime.capability()))
        .collect::<Vec<_>>()
        .join("\n");
    let brief = BRIEF
        .replace("%RUNTIMES%", &runtimes)
        .replace("%TASK%", &forge_request.task);

    let program =
        ask_model(backend, model, &brief, timeout_secs).map_err(|error| error.to_string())?;

    let work = crate::agent::tempdir().map_err(|error| error.to_string())?;
    let work = work.path();
    let (code, proof) =
        match forge::build_and_verify(program.source.as_bytes(), &work.join("forge")) {
            Ok(built) => built,
            Err(forge::ForgeError::Build(stderr)) => {
                return Err(format!("the generated program does not compile:\n{stderr}"));
            }
            Err(error) => return Err(error.to_string()),
        };

    celln_control::check().map_err(|e| e.to_string())?;
    let mut assayer = assay::Assayer::open(assay_root).map_err(|error| error.to_string())?;
    let hash = assayer
        .admit_forged_authored(ALIAS, &code, false, celln_manifest::Author::Agent, &proof)
        .map_err(|error| error.to_string())?;

    Ok(ForgedProgram {
        hash: hash.0,
        bytes: code,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn forge(
    _forge_request: &ForgeRequest,
    _assay_root: &Path,
    _timeout_secs: u64,
) -> Result<ForgedProgram, String> {
    Err("forging a program needs Linux with /dev/kvm".to_owned())
}

/// Seal and run `program_bytes` — the exact resolved bytes for a declared
/// request (`resolve_bundle` verified their hash matches what was declared),
/// or the exact bytes `forge` just wrote and admitted, for a forge-from-task
/// request. Either way, by the time this is called, the authority is a real
/// hash of real bytes, not a name or a task string.
///
/// This reuses the same toolfs/initrd build and `LinuxCell` boot sequence as
/// `celln agent`. The guest still boots this host's own kernel
/// (`BootConfig::host_kernel()`) — a declared request's mote bundle
/// `kernel`/`initrd` hashes are verified to exist and match, but actually
/// booting an arbitrary stored kernel image would need its `/lib/modules`
/// alongside it, which the mote bundle contract does not carry yet. That
/// remains a known gap, not a hidden one.
#[cfg(target_os = "linux")]
pub fn launch(
    request: &ExecutionRequest,
    alias: &str,
    args: &[String],
    program_bytes: &[u8],
    runtime_root: &Path,
    assay_root: &Path,
    state_root: &Path,
) -> Result<LaunchOutcome, String> {
    use warden::vmm::boot::BootConfig;

    check_supported_authority(request)?;
    if request.mote.is_some() {
        return Err("declared execution requires the pinned substrate launcher".into());
    }
    let inputs = inputs::resolve(request, state_root)?;
    if !Path::new("/dev/kvm").exists() {
        return Err("no /dev/kvm — cannot seal a cell on this host".to_owned());
    }

    // Admit the bytes into this node's own attested manifest so pilot's exec
    // gate has an entry to check against. For a declared request the hash
    // this computes lines up with the request's own declared hash by
    // construction — `resolve_bundle` already proved that. Preserve any entry
    // already admitted upstream, including its authorship and proof.
    let mut assayer = assay::Assayer::open(assay_root).map_err(|error| error.to_string())?;
    // Forge has already recorded agent authorship and its proof. Re-admitting
    // those bytes as Host would silently promote them back to the tool lane.
    // Existing provenance is authoritative; a requested lane can only narrow it.
    if assayer.manifest().get(&Hash::of(program_bytes)).is_none() {
        assayer
            .admit_verified(alias, program_bytes, false)
            .map_err(|error| error.to_string())?;
    }

    let work = crate::agent::tempdir().map_err(|error| error.to_string())?;
    let work = work.path();
    // The toolfs mount path is fixed by this file's own name — mktoolfs.sh
    // seals it into the image root under this basename, so pilot finds it at
    // `/tools/program` regardless of what alias the request declares. The
    // alias is a separate, arbitrary manifest lookup key (celln-spec.Tool
    // conventions), not the mount path.
    let bin = work.join("program");
    std::fs::write(&bin, program_bytes).map_err(|error| error.to_string())?;

    let run_json = work.join("run.json");
    std::fs::write(
        &run_json,
        serde_json::to_vec_pretty(&serde_json::json!({
            "path": "/tools/program",
            "alias": alias,
            "args": args,
            "agent_authored_input": matches!(request.execution.lane, RequestedLane::Agent),
            "allow_fetch": !request.capabilities.egress.is_empty(),
            "report_output_limit": request.capabilities.output_bytes,
            "force_agent_lane": matches!(request.execution.lane, RequestedLane::Agent),
            "workspace_access": request.capabilities.workspace,
            "inputs": inputs,
        }))
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;

    let toolfs = work.join("toolfs.img");
    crate::agent::sh(
        runtime_root,
        "scripts/mktoolfs.sh",
        &[
            toolfs.display().to_string(),
            "32".into(),
            bin.display().to_string(),
        ],
    )
    .map_err(|error| error.to_string())?;

    let initrd = work.join("initramfs.cpio");
    crate::agent::sh_env(
        runtime_root,
        "scripts/mkinitramfs.sh",
        &[initrd.display().to_string()],
        &[
            (
                "CELLN_MANIFEST",
                assay_root.join("manifest.json").display().to_string(),
            ),
            ("CELLN_WARM_DISPATCH", "1".into()),
            ("CELLN_RUN_JSON", String::new()),
            (
                "CELLN_PILOT_DIR",
                runtime_root.join("pilot").display().to_string(),
            ),
        ],
    )
    .map_err(|error| error.to_string())?;

    let kernel = BootConfig::host_kernel()
        .ok_or_else(|| "no readable /boot/vmlinuz-* with matching /lib/modules".to_owned())?;
    let payload = std::fs::read(&toolfs).map_err(|error| error.to_string())?;
    let cfg = BootConfig::new(&kernel)
        .with_pmem(payload.len())
        .with_initrd(&initrd);
    let invocation = std::fs::read(run_json).map_err(|e| e.to_string())?;
    run_prepared(
        request,
        alias,
        cfg,
        payload,
        &invocation,
        state_root,
        Hash::of(program_bytes).0,
    )
}

#[cfg(target_os = "linux")]
fn run_prepared(
    request: &ExecutionRequest,
    alias: &str,
    mut cfg: warden::vmm::boot::BootConfig,
    payload: Vec<u8>,
    invocation: &[u8],
    state_root: &Path,
    program_hash: String,
) -> Result<LaunchOutcome, String> {
    if invocation.len() > warden::MAX_INVOCATION_BYTES {
        return Err("invocation exceeds bounded delivery channel".into());
    }
    if request.capabilities.memory_bytes > 0 {
        cfg.mem_size = request.capabilities.memory_bytes as usize;
    }
    cfg.timeout = std::time::Duration::from_millis(request.capabilities.timeout_ms.max(1));

    let kernel_hash = Hash::of(&std::fs::read(&cfg.kernel).map_err(|e| e.to_string())?);
    let initrd_hash = Hash::of(
        &std::fs::read(cfg.initrd.as_ref().ok_or("initrd required")?).map_err(|e| e.to_string())?,
    );
    let key = format!(
        "forge:{kernel_hash}:{initrd_hash}:{}:{}",
        Hash::of(&payload),
        cfg.mem_size
    );
    let identity = SubstrateIdentity {
        closure: None,
        kernel: kernel_hash.0,
        initrd: initrd_hash.0,
        toolfs: Hash::of(&payload).0,
        invocation: Hash::of(invocation).0,
    };
    let mut cell = warm::fork(key, vec![program_hash.clone()], || Ok((cfg, payload)))?;
    cell.set_invocation(invocation).map_err(|e| e.to_string())?;
    let mut outcome = run_cell(request, alias, cell, state_root)?;
    outcome.substrate = Some(identity);
    validate_executed_tool(&mut outcome, &program_hash);
    Ok(outcome)
}

fn validate_executed_tool(outcome: &mut LaunchOutcome, expected: &str) {
    if outcome
        .execution
        .as_ref()
        .is_some_and(|grant| grant.tool != expected)
    {
        outcome.execution = None;
        outcome.denial = Some("executed tool report mismatch".into());
    }
}

#[cfg(target_os = "linux")]
fn run_cell(
    request: &ExecutionRequest,
    alias: &str,
    mut cell: warden::vmm::boot::LinuxCell,
    state_root: &Path,
) -> Result<LaunchOutcome, String> {
    cell.set_timeout(std::time::Duration::from_millis(
        request.capabilities.timeout_ms.max(1),
    ));

    let name = truncate_for_description(&request.workload.id);
    let mut record = crate::cells::begin(
        state_root,
        &name,
        Path::new("<execution-request>"),
        vec![alias.to_owned()],
    )
    .ok();
    let cell_id = record
        .as_ref()
        .map(|record| record.id.clone())
        .unwrap_or_default();

    if request.harness.is_none() && !request.capabilities.egress.is_empty() {
        let hosts: Vec<String> = request
            .capabilities
            .egress
            .iter()
            .filter_map(|destination| destination.strip_prefix("https://"))
            .map(str::to_owned)
            .collect();
        cell.enable_http_fetch(warden::egress::HttpPolicy::new(hosts));
    }
    let running_at = now_rfc3339();
    let running_observed = std::time::Instant::now();
    let report = match cell.run() {
        Ok(report) => report,
        Err(error) => {
            if let Some(record) = record.as_mut() {
                crate::cells::finish(state_root, record, "kvm", Some(error.to_string()));
            }
            return Err(error.to_string());
        }
    };

    let mut outcome = parse_report(
        &report.console,
        cell_id,
        request.capabilities.output_bytes as usize,
        report.end == warden::vmm::boot::BootEnd::TimedOut,
        report.end == warden::vmm::boot::BootEnd::Shutdown,
    );
    let (requests, denied, response_bytes) = cell.fetch_activity();
    outcome.broker = BrokerActivity {
        requests,
        denied,
        response_bytes,
    };
    if let Some(reason) = celln_control::current().and_then(|c| c.reason()) {
        outcome.denial = Some(reason.to_string());
    }
    let expected: Vec<_> = request.inputs.iter().map(|i| i.hash.clone()).collect();
    if let Some(grant) = &outcome.execution {
        let workspace = serde_json::to_value(request.capabilities.workspace).unwrap();
        if grant.workspace.as_deref() != workspace.as_str()
            || grant.fetch != !request.capabilities.egress.is_empty()
            || !matches!(grant.lane.as_str(), "agent" | "tool")
            || (request.execution.lane == RequestedLane::Agent && grant.lane != "agent")
        {
            outcome.execution = None;
            outcome.denial = Some("executed authority report mismatch".into());
        }
    } else if outcome.exit_code.is_some() || outcome.signal.is_some() {
        outcome.denial = Some("missing pilot execution grant report".into());
    }
    if outcome.input_hashes != expected {
        outcome.input_hashes.clear();
        outcome
            .denial
            .get_or_insert_with(|| "input delivery report mismatch".into());
    }
    drop(cell);
    outcome.lifecycle = vec![
        CellEvent {
            phase: "CellRunning".into(),
            at: running_at,
            observed: running_observed,
        },
        CellEvent {
            phase: "Dissolved".into(),
            at: now_rfc3339(),
            observed: std::time::Instant::now(),
        },
    ];
    if let Some(record) = record.as_mut() {
        crate::cells::finish(state_root, record, "kvm", outcome.denial.clone());
    }
    Ok(outcome)
}

#[cfg(not(target_os = "linux"))]
pub fn launch(
    request: &ExecutionRequest,
    _alias: &str,
    _args: &[String],
    _program_bytes: &[u8],
    _runtime_root: &Path,
    _assay_root: &Path,
    _state_root: &Path,
) -> Result<LaunchOutcome, String> {
    check_supported_authority(request)?;
    Err("sealing cells needs Linux with /dev/kvm".to_owned())
}

#[cfg(target_os = "linux")]
fn truncate_for_description(id: &str) -> String {
    if id.len() <= 30 {
        return id.to_owned();
    }
    let mut end = 30;
    while !id.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &id[..end])
}

/// `YYYY-MM-DDTHH:MM:SSZ`, computed from a Unix timestamp with no calendar
/// dependency. [Howard Hinnant's `civil_from_days`](http://howardhinnant.github.io/date_algorithms.html),
/// which this workspace has no `chrono`/`time` crate pinned to reach for.
pub fn rfc3339_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs_of_day = unix_seconds.rem_euclid(86_400);
    let (hour, minute, second) = (
        secs_of_day / 3600,
        (secs_of_day / 60) % 60,
        secs_of_day % 60,
    );

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Now, as an RFC3339 UTC timestamp.
pub fn now_rfc3339() -> String {
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    rfc3339_utc(unix_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use celln_spec::ExecutionRequest;
    use celln_store::Store;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn unsupported_authority_refuses_before_resolution_or_launch() {
        let base: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1", "id": "authority-test",
            "workload": { "id": "test", "caller": "test" },
            "mote": { "hash": Hash::of(b"mote").0 },
            "tools": [{ "alias": "/tools/program", "hash": Hash::of(b"program").0 }],
            "invocation": { "alias": "/tools/program" },
            "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 268435456, "outputBytes": 1024 },
            "execution": { "lane": "agent", "requireHardwareIsolation": true }
        })).unwrap();
        assert!(base.problems().is_empty());
        assert!(check_supported_authority(&base).is_ok());
        let mut cases = Vec::new();
        let mut input = base.clone();
        input.inputs.push(celln_spec::ExecutionInput {
            name: "data".into(),
            hash: Hash::of(b"data").0,
            media_type: "text/plain".into(),
            bytes: 4,
        });
        cases.push((input, "inputs require"));
        for access in [
            celln_spec::WorkspaceAccess::ReadOnly,
            celln_spec::WorkspaceAccess::ReadWrite,
        ] {
            let mut workspace = base.clone();
            workspace.capabilities.workspace = access;
            assert!(check_supported_authority(&workspace).is_ok());
        }
        let mut closure = base.clone();
        closure.tools[0].closure = Some(celln_spec::ImmutableRef {
            hash: Hash::of(b"closure").0,
        });
        closure.capabilities.egress = vec!["https://example.com".into()];
        cases.push((closure, "closure delivery"));
        let mut extra = base.clone();
        extra.tools.push(celln_spec::ToolRef {
            alias: "/tools/extra".into(),
            hash: Hash::of(b"extra").0,
            closure: None,
        });
        cases.push((extra, "only the invoked tool"));
        let work = tempdir().unwrap();
        let missing = work.path().join("must-not-be-created");
        for (request, reason) in cases {
            assert!(request.problems().is_empty());
            let error = resolve_bundle(&request, &missing, &missing).unwrap_err();
            assert!(error.contains(reason), "{error}");
            let error = launch(
                &request,
                "program",
                &[],
                b"program",
                &missing,
                &missing,
                &missing,
            )
            .unwrap_err();
            assert!(error.contains(reason), "{error}");
            assert!(!missing.exists());
        }
    }

    #[test]
    fn resolved_bundle_binds_the_requested_invocation_to_the_declared_tool() {
        let motes = tempdir().expect("mote store");
        let tools = tempdir().expect("tool store");
        let tool_store = Store::open(tools.path()).expect("open tool store");
        let tool_hash = tool_store.put(b"static-program").expect("store program");
        let mote_store = Store::open(motes.path()).expect("open mote store");
        let kernel_hash = mote_store.put(b"kernel").expect("store kernel");
        let initrd_hash = mote_store.put(b"initrd").expect("store initrd");
        let toolfs_hash = mote_store.put(b"toolfs").expect("store toolfs");
        let bundle = json!({
            "apiVersion": "celln.dev/v1alpha1",
            "kernel": kernel_hash.0,
            "initrd": initrd_hash.0,
            "toolfs": toolfs_hash.0,
            "invocation": { "alias": "/tools/program", "toolHash": tool_hash.0 }
        });
        let mote_hash = mote_store
            .put(&serde_json::to_vec(&bundle).expect("bundle serializes"))
            .expect("store bundle");
        let request: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1",
            "id": "one-shot-1",
            "workload": { "id": "one-shot", "caller": "sympozium:default/one-shot-1" },
            "mote": { "hash": mote_hash.0 },
            "tools": [{ "alias": "/tools/program", "hash": tool_hash.0 }],
            "invocation": { "alias": "/tools/program", "args": [] },
            "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 268435456, "outputBytes": 1024 },
            "execution": { "lane": "agent", "requireHardwareIsolation": true }
        }))
        .expect("request parses");

        let resolved =
            resolve_bundle(&request, motes.path(), tools.path()).expect("bundle resolves");
        assert_eq!(resolved.program_hash, tool_hash.0);
        assert_eq!(resolved.bundle_hash, mote_hash.0);
        assert_eq!(resolved.kernel_hash, kernel_hash.0);
        assert_eq!(resolved.initrd_hash, initrd_hash.0);
        assert_eq!(resolved.toolfs_hash, toolfs_hash.0);
    }

    /// `celln node resolve-file` calls `resolve_bundle` directly on a request
    /// that was never run through `admit` (that's deliberate — resolution and
    /// admission are separate commands). A malformed hash must still be
    /// refused here, not only by whichever caller happens to run `problems()`
    /// first, and never reach `Store::get` at all.
    #[test]
    fn a_malformed_mote_hash_is_refused_before_any_store_lookup_even_without_prior_admission() {
        let motes = tempdir().expect("mote store");
        let tools = tempdir().expect("tool store");
        let request: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1",
            "id": "traversal-1",
            "workload": { "id": "traversal", "caller": "sympozium:default/traversal-1" },
            "mote": { "hash": "blake3:/etc/passwd" },
            "tools": [{ "alias": "/tools/program", "hash": "blake3:/etc/shadow" }],
            "invocation": { "alias": "/tools/program", "args": [] },
            "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 268435456, "outputBytes": 1024 },
            "execution": { "lane": "agent", "requireHardwareIsolation": true }
        }))
        .expect("request parses — shape is valid JSON even though the hashes aren't");

        let error =
            resolve_bundle(&request, motes.path(), tools.path()).expect_err("must be refused");
        assert!(
            error.contains("mote.hash") || error.contains("invalid"),
            "error should name the bad field, got: {error}"
        );
        // Confirm this was refused before ever touching the store: an empty
        // store root has no `objects/` entries to find, but the point is the
        // request never got far enough to try.
        assert!(std::fs::read_dir(motes.path().join("objects"))
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(true));
    }

    #[test]
    fn rfc3339_utc_handles_a_pre_epoch_date() {
        // 1969-12-31T23:59:59Z — one second before the epoch, the standard
        // edge case for a from-scratch civil calendar conversion.
        assert_eq!(rfc3339_utc(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    #[ignore = "requires KVM, guest kernel, musl and built pilot binaries"]
    #[cfg(target_os = "linux")]
    fn dispatch_outcomes_on_real_kvm() {
        let _proof = super::warm::PROOF_LOCK.lock().unwrap();
        use std::process::Command;
        if !Path::new("/dev/kvm").exists() || warden::vmm::boot::BootConfig::host_kernel().is_none()
        {
            eprintln!("skipping: KVM or readable matching kernel unavailable");
            return;
        }
        let work = tempdir().unwrap();
        let Some(runtime) = test_runtime_root(work.path()) else {
            return;
        };
        let binary = work.path().join("outcome-probe");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dispatch_outcome_probe.rs");
        assert!(Command::new("rustc")
            .args([
                "--edition=2021",
                "-O",
                "--target",
                "x86_64-unknown-linux-musl",
                "-o"
            ])
            .arg(&binary)
            .arg(source)
            .status()
            .unwrap()
            .success());
        let bytes = std::fs::read(binary).unwrap();
        let mut request: ExecutionRequest =
            serde_json::from_str(include_str!("../../../examples/execution/forge-task.json"))
                .unwrap();
        request.capabilities.timeout_ms = 8000;
        request.capabilities.output_bytes = 1024;
        request.capabilities.egress.clear();
        for (mode, code, signal, timeout) in [
            ("silent", Some(0), None, false),
            ("failed", Some(7), None, false),
            ("signal", None, Some(6), false),
            ("spoof", Some(9), None, false),
            ("flood", Some(0), None, false),
            ("timeout", None, None, true),
        ] {
            let state = work.path().join(format!("state-{mode}"));
            std::fs::create_dir_all(&state).unwrap();
            let outcome = launch(
                &request,
                "/agent/program",
                &[mode.into()],
                &bytes,
                &runtime,
                &work.path().join("assay"),
                &state,
            )
            .unwrap();
            assert_eq!(outcome.exit_code, code, "{mode}: {outcome:?}");
            assert_eq!(outcome.signal, signal, "{mode}: {outcome:?}");
            assert_eq!(outcome.timed_out, timeout, "{mode}: {outcome:?}");
            assert_eq!(outcome.succeeded(), code == Some(0), "{mode}: {outcome:?}");
            let output = outcome.output.as_deref().unwrap();
            match mode {
                "silent" => assert!(output.is_empty()),
                "failed" => assert_eq!(output, b"failure detail\n"),
                "spoof" => assert!(String::from_utf8_lossy(output).contains("CELLN:dispatch=")),
                "flood" => assert_eq!(output.len(), 1024),
                "timeout" => assert!(String::from_utf8_lossy(output).contains("before timeout")),
                _ => {}
            }
            assert_eq!(
                crate::cells::live_count(&state),
                0,
                "{mode} left a live record"
            );
            eprintln!("PASS: {mode}, exit={code:?}, signal={signal:?}, timeout={timeout}");
        }
        let outcome = launch(
            &request,
            "/invalid",
            &[],
            b"not executable",
            &runtime,
            &work.path().join("assay"),
            &work.path().join("invalid-state"),
        )
        .unwrap();
        assert!(!outcome.succeeded());
        assert_eq!(outcome.denial.as_deref(), Some("pilot exec setup failed"));
        assert!(outcome.execution.is_none());
        // An agent artifact stays in the agent lane even if a later caller
        // asks for the tool lane. The spoof probe also attempts unshare.
        let assay_root = work.path().join("assay");
        let mut assayer = assay::Assayer::open(&assay_root).unwrap();
        let hash = assayer
            .admit_verified_authored(
                "/agent/program",
                &bytes,
                false,
                celln_manifest::Author::Agent,
            )
            .unwrap();
        request.execution.lane = RequestedLane::Tool;
        let outcome = launch(
            &request,
            "/agent/program",
            &["spoof".into()],
            &bytes,
            &runtime,
            &assay_root,
            &work.path().join("preserved-author"),
        )
        .unwrap();
        assert_eq!(outcome.execution.as_ref().unwrap().lane, "agent");
        assert_eq!(outcome.execution.as_ref().unwrap().tool, hash.0);
        assert_eq!(outcome.exit_code, Some(9), "{outcome:?}");
        assert_eq!(
            assay::Assayer::open(&assay_root)
                .unwrap()
                .manifest()
                .get(&hash)
                .unwrap()
                .author,
            celln_manifest::Author::Agent
        );
        assayer.revoke(&hash);
        let outcome = launch(
            &request,
            "/agent/program",
            &["silent".into()],
            &bytes,
            &runtime,
            &assay_root,
            &work.path().join("refused-state"),
        )
        .unwrap();
        assert!(!outcome.succeeded());
        assert_eq!(outcome.denial.as_deref(), Some("pilot refused execution"));
        assert!(outcome.execution.is_none());
        eprintln!("PASS: exec setup failure, retained agent lane, and pilot refusal");
    }

    /// A runtime root the launch pipeline can build an initrd/toolfs from,
    /// borrowing this checkout's scripts and this workspace's own
    /// already-built guest pilot binaries. `None` (with an explanatory
    /// `eprintln!`) if the guest pilot binaries haven't been built.
    #[cfg(target_os = "linux")]
    pub(super) fn test_runtime_root(work: &Path) -> Option<std::path::PathBuf> {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."); // crates/celln-cli -> repo root
        let repo_root = repo_root.canonicalize().expect("repo root resolves");
        let pilot_dir = std::env::var_os("CELLN_PILOT_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| repo_root.join("target/x86_64-unknown-linux-musl/release"));
        if !pilot_dir.join("celln-pilot").exists() || !pilot_dir.join("pilot-fetch").exists() {
            eprintln!(
                "skipping: guest pilot binaries not built — run \
                 `cargo build --release --target x86_64-unknown-linux-musl -p celln-pilot \
                 --bin celln-pilot --bin pilot-fetch` first"
            );
            return None;
        }
        let runtime_root = work.join("runtime");
        std::fs::create_dir_all(runtime_root.join("scripts")).unwrap();
        std::fs::create_dir_all(runtime_root.join("pilot")).unwrap();
        std::fs::create_dir_all(runtime_root.join("guest/init")).unwrap();
        for script in ["mktoolfs.sh", "mkinitramfs.sh"] {
            std::fs::copy(
                repo_root.join("scripts").join(script),
                runtime_root.join("scripts").join(script),
            )
            .unwrap_or_else(|e| panic!("copying {script}: {e}"));
        }
        std::fs::copy(
            repo_root.join("guest/init/init.c"),
            runtime_root.join("guest/init/init.c"),
        )
        .expect("copy guest init.c");
        std::fs::copy(
            pilot_dir.join("celln-pilot"),
            runtime_root.join("pilot/celln-pilot"),
        )
        .expect("copy celln-pilot");
        std::fs::copy(
            pilot_dir.join("pilot-fetch"),
            runtime_root.join("pilot/pilot-fetch"),
        )
        .expect("copy pilot-fetch");
        Some(runtime_root)
    }

    /// Full forge-from-task pipeline, on real hardware: a real,
    /// already-authenticated backend writes a program from a task string,
    /// `forge` builds/admits it, and `launch` seals and runs the exact bytes
    /// that came back — no pre-declared mote or tool at all. Defaults to
    /// `anthropic`; CELLN_TEST_FORGE_BACKEND explicitly selects another backend. This makes a real,
    /// possibly billed, call. Not run by default — needs /dev/kvm, the
    /// guest pilot binaries, and `claude` authenticated on this host. Run
    /// explicitly with:
    ///   cargo test -p celln-cli -- --ignored forge_actually_writes_builds_and_runs_a_program
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn forge_actually_writes_builds_and_runs_a_program() {
        if !Path::new("/dev/kvm").exists() {
            eprintln!("skipping: no /dev/kvm on this runner");
            return;
        }
        let backend =
            std::env::var("CELLN_TEST_FORGE_BACKEND").unwrap_or_else(|_| "anthropic".into());
        let provider =
            crate::agent::Backend::from_saved_name(&backend).expect("known explicit test backend");
        if !provider.available() {
            eprintln!("skipping: selected backend is unavailable — see `celln providers`");
            return;
        }

        let work = tempdir().expect("work dir");
        let Some(runtime_root) = test_runtime_root(work.path()) else {
            return;
        };

        let request: ExecutionRequest = serde_json::from_value(json!({
            "apiVersion": "celln.dev/v1alpha1",
            "id": "forge-smoke-test",
            "workload": { "id": "smoke-test", "caller": "test:forge" },
            "forge": { "task": "print exactly the line: hello from a forged execution request", "backend": backend },
            "capabilities": { "workspace": "none", "timeoutMs": 90000, "memoryBytes": 268435456, "outputBytes": 65536 },
            "execution": { "lane": "agent", "requireHardwareIsolation": true }
        }))
        .expect("request parses");
        assert!(request.problems().is_empty(), "{:?}", request.problems());

        let assay_root = work.path().join("assay");
        let state_root = work.path().join("state");
        std::fs::create_dir_all(&state_root).unwrap();

        let forge_request = request.forge.as_ref().unwrap();
        let forged = forge(
            forge_request,
            &assay_root,
            request.capabilities.timeout_ms / 1000,
        )
        .expect("forge writes, builds, and admits a program");
        assert!(!forged.bytes.is_empty());
        assert_eq!(forged.hash, celln_manifest::Hash::of(&forged.bytes).0);

        let outcome = launch(
            &request,
            crate::agent::ALIAS,
            &[],
            &forged.bytes,
            &runtime_root,
            &assay_root,
            &state_root,
        )
        .expect("cell launches and runs");

        assert!(outcome.succeeded(), "{outcome:?}");
        assert_eq!(outcome.execution.as_ref().unwrap().lane, "agent");
        assert_eq!(outcome.execution.as_ref().unwrap().tool, forged.hash);
        assert_eq!(crate::cells::live_count(&state_root), 0);
        eprintln!(
            "PASS: real {backend} model → reproduced program {} → sealed KVM execution → dissolved",
            forged.hash
        );

        assert!(
            outcome.denial.is_none(),
            "pilot denied it: {:?}",
            outcome.denial
        );
        let output = outcome.output.expect("program produced output");
        let output = String::from_utf8(output).expect("output is utf8");
        assert!(
            output.to_lowercase().contains("hello"),
            "unexpected output: {output:?}"
        );
    }
}
