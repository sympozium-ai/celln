//! Strict TOML cell specifications.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A cell specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub name: String,

    #[serde(default)]
    pub cell: Cell,

    #[serde(default, rename = "tool")]
    pub tools: Vec<Tool>,

    #[serde(default, rename = "run")]
    pub run: Option<Runs>,

    /// Let a model write what this cell runs. The spec stays the policy — the
    /// tools, the memory, the hosts — and only the code is filled in.
    #[serde(default)]
    pub agent: Option<AgentTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTask {
    /// What the provider should make the cell do. `--prompt` overrides it.
    ///
    /// `task` was the original spelling. Read it so existing reviewed specs
    /// remain valid, but always emit and document the clearer `prompt` name.
    #[serde(default, alias = "task")]
    pub prompt: Option<String>,
    /// Which declared tool receives the provider's program or arguments.
    pub exec: String,
}

/// A cell may run one tool or several. `[run]` is one, `[[run]]` is a list;
/// each invocation is hash-checked and lane-resolved on its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Runs {
    One(Box<Run>),
    Many(Vec<Run>),
}

impl Runs {
    pub fn as_slice(&self) -> Vec<&Run> {
        match self {
            Runs::One(r) => vec![r.as_ref()],
            Runs::Many(v) => v.iter().collect(),
        }
    }
}

impl Spec {
    /// Every declared invocation, in order.
    pub fn run_list(&self) -> Vec<&Run> {
        self.run.as_ref().map(Runs::as_slice).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    #[serde(default = "default_memory")]
    pub memory: String,

    #[serde(default = "default_tier")]
    pub require_tier: Tier,

    /// Exact DNS names the host will fetch on this cell's behalf. Empty means
    /// the cell is hermetic. This is a host capability, not a network: the
    /// guest has no stack, and every URL is validated host-side.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            memory: default_memory(),
            require_tier: default_tier(),
            allow_hosts: Vec::new(),
        }
    }
}

fn default_memory() -> String {
    "256MiB".into()
}
fn default_tier() -> Tier {
    Tier::Verified
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Forged,
    Verified,
    Unsealed,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Tier::Forged => "forged",
            Tier::Verified => "verified",
            Tier::Unsealed => "unsealed",
        })
    }
}

/// One tool the cell may be lent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    /// The name the agent uses, e.g. `/usr/bin/python`. A naming convenience:
    /// authority comes from the content hash, never from this path.
    pub alias: String,

    /// Where the bytes come from on this host. One of `path` or `image`.
    #[serde(default)]
    pub path: Option<PathBuf>,

    /// A digest-pinned OCI reference whose whole filesystem is lent, for tools
    /// that are a dependency closure rather than one file. Materialise it with
    /// `celln image pull` first.
    #[serde(default)]
    pub image: Option<String>,

    /// Path to execute *inside* `image`.
    #[serde(default)]
    pub exec: Option<String>,

    /// A capability the host provides rather than bytes it lends. Only
    /// `"fetch"` today: the bounded HTTPS fetch, which needs `allow_hosts`.
    #[serde(default)]
    pub builtin: Option<String>,

    /// True for interpreters (python, sh, node…). An interpreter fed input the
    /// agent wrote is moved to the agent lane *for that invocation* — the
    /// laundering ban. Getting this wrong is the most consequential mistake
    /// available in this file, which is why `celln spec check` guesses at it and
    /// warns when your answer disagrees.
    #[serde(default)]
    pub interpreter: bool,
}

/// What the agent intends to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    /// Which tool alias to execute.
    pub exec: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Provenance of what it is being fed. `data` means the agent produced it,
    /// which demotes an interpreter.
    #[serde(default)]
    pub input: Input,
}

/// Where the input to an exec came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Input {
    /// Nothing interpreted (e.g. `ls`).
    #[default]
    None,
    /// A file that came in through the attestation gate.
    Tool,
    /// A file the agent wrote. Demotes an interpreter.
    Data,
}

/// Versioned, transport-neutral intent submitted by a control plane.
///
/// This is deliberately not a Kubernetes object. A Kubernetes controller may
/// carry it in a CR or send it to a node agent, but the execution boundary only
/// receives this request and returns an execution verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRequest {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub id: String,
    pub workload: WorkloadIdentity,
    /// The declared mote/tool source. Exactly one of `mote` or `forge` must
    /// be set — a request either names a pre-declared, hash-pinned program,
    /// or asks for one to be written. See [`ExecutionRequest::problems`].
    #[serde(default)]
    pub mote: Option<ImmutableRef>,
    /// Immutable data supplied by an orchestration edge. It can become
    /// workspace data but never executable authority.
    #[serde(default)]
    pub inputs: Vec<ExecutionInput>,
    #[serde(default)]
    pub tools: Vec<ToolRef>,
    /// The one declared executable selected from `tools`. Admission may be
    /// performed before an executable is chosen, so dispatchers require this
    /// field while the base request remains backward compatible. Must not be
    /// set together with `forge` — there is nothing pre-declared to invoke.
    #[serde(default)]
    pub invocation: Option<Invocation>,
    /// The forge-from-task alternative to a declared `mote`/`tools`/
    /// `invocation`. The dispatcher asks a model to write the program,
    /// admits the real bytes it gets back — real hash, `author=agent` — and
    /// only then resolves/seals/runs it. The task string itself is never
    /// executable authority; the hash computed after compilation is. Mutually
    /// exclusive with `mote`, and requires `execution.lane: agent`, since
    /// forged code is never tool-lane authority.
    #[serde(default)]
    pub forge: Option<ForgeRequest>,
    pub capabilities: CapabilityRequest,
    pub execution: ExecutionPolicy,
}

/// See [`ExecutionRequest::forge`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgeRequest {
    pub task: String,
    /// Which backend writes it: `"anthropic" | "openai" | "deepseek" |
    /// "local"`. Unset means the dispatcher's own discovery order.
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    pub id: String,
    pub caller: String,
}

/// A content-addressed object. Names, tags, and paths are not executable
/// authority at the execution boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableRef {
    pub hash: String,
}

/// Content-addressed data handed from one workload to another.
///
/// `assay` resolves this reference from an immutable store before `warden`
/// makes the bytes visible in a cell workspace. It is never a tool reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionInput {
    pub name: String,
    pub hash: String,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRef {
    pub alias: String,
    pub hash: String,
    #[serde(default)]
    pub closure: Option<ImmutableRef>,
}

/// A concrete exec-by-hash request. `alias` is only a lookup into the declared
/// tool set; the selected tool's immutable hash remains the authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub alias: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    pub workspace: WorkspaceAccess,
    #[serde(default)]
    pub egress: Vec<String>,
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
    #[serde(rename = "memoryBytes")]
    pub memory_bytes: u64,
    #[serde(rename = "outputBytes")]
    pub output_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceAccess {
    None,
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    pub lane: RequestedLane,
    #[serde(rename = "requireHardwareIsolation")]
    pub require_hardware_isolation: bool,
}

/// A terminal execution record returned by a Celln dispatcher.
///
/// The control plane uses this rather than container logs as the authoritative
/// result. Every reference in the receipt is content-addressed, so a successor
/// workload can consume output without converting a mutable status field into
/// authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub phase: ExecutionPhase,
    pub node: String,
    #[serde(rename = "cellId")]
    pub cell_id: String,
    pub resolved: ResolvedExecution,
    #[serde(default)]
    pub output: Option<ExecutionOutput>,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedExecution {
    /// The mote bundle this ran from, if the request declared one. `None`
    /// for a forge-from-task request — there is no pre-existing bundle,
    /// only the program `tools[]` names after the fact.
    #[serde(default)]
    pub mote: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOutput {
    pub hash: String,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestedLane {
    Tool,
    Agent,
}

/// A stable validation failure suitable for a transport response or a control
/// plane condition. It never names a host path or another capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionProblemCode {
    UnsupportedVersion,
    MissingIdentity,
    MutableReference,
    InvalidToolAlias,
    DuplicateToolAlias,
    InvalidInputName,
    DuplicateInputName,
    UndeclaredInvocation,
    InvalidInvocationArgument,
    InvalidEgress,
    InvalidLimit,
    InvalidForge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProblem {
    pub code: ExecutionProblemCode,
    pub field: String,
    pub message: String,
}

impl ExecutionRequest {
    /// Validate intent before any node is selected. Host eligibility and tool
    /// availability are deliberately separate decisions made by the node agent.
    pub fn problems(&self) -> Vec<ExecutionProblem> {
        let mut problems = Vec::new();
        if self.api_version != "celln.dev/v1alpha1" {
            problems.push(ExecutionProblem {
                code: ExecutionProblemCode::UnsupportedVersion,
                field: "apiVersion".into(),
                message: "must be celln.dev/v1alpha1".into(),
            });
        }
        for (field, value) in [
            ("id", self.id.as_str()),
            ("workload.id", self.workload.id.as_str()),
            ("workload.caller", self.workload.caller.as_str()),
        ] {
            if value.trim().is_empty() {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::MissingIdentity,
                    field: field.into(),
                    message: "must not be empty".into(),
                });
            }
        }
        match (&self.mote, &self.forge) {
            (Some(mote), None) => {
                if !is_immutable_hash(&mote.hash) {
                    problems.push(mutable_reference("mote.hash"));
                }
            }
            (None, Some(forge)) => {
                if forge.task.trim().is_empty() {
                    problems.push(ExecutionProblem {
                        code: ExecutionProblemCode::InvalidForge,
                        field: "forge.task".into(),
                        message: "must not be empty".into(),
                    });
                }
                if self.execution.lane != RequestedLane::Agent {
                    problems.push(ExecutionProblem {
                        code: ExecutionProblemCode::InvalidForge,
                        field: "execution.lane".into(),
                        message: "must be \"agent\" when forge is set — forged code is never tool-lane authority".into(),
                    });
                }
                if self.invocation.is_some() {
                    problems.push(ExecutionProblem {
                        code: ExecutionProblemCode::InvalidForge,
                        field: "invocation".into(),
                        message: "must not be set together with forge — there is no pre-declared tool to invoke".into(),
                    });
                }
                if !self.tools.is_empty() {
                    problems.push(ExecutionProblem {
                        code: ExecutionProblemCode::InvalidForge,
                        field: "tools".into(),
                        message: "must be empty when forge is set — nothing is pre-declared".into(),
                    });
                }
            }
            (Some(_), Some(_)) => {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidForge,
                    field: "mote".into(),
                    message:
                        "must not be set together with forge — pick exactly one execution source"
                            .into(),
                });
            }
            (None, None) => {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidForge,
                    field: "mote".into(),
                    message: "must be set, or forge must be set — a request needs exactly one execution source".into(),
                });
            }
        }

        for (index, input) in self.inputs.iter().enumerate() {
            let prefix = format!("inputs[{index}]");
            if !is_input_name(&input.name) {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidInputName,
                    field: format!("{prefix}.name"),
                    message: "must be a non-empty lowercase name containing only letters, numbers, dots, underscores, or hyphens".into(),
                });
            }
            if !is_immutable_hash(&input.hash) {
                problems.push(mutable_reference(&format!("{prefix}.hash")));
            }
            if input.media_type.trim().is_empty() {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidLimit,
                    field: format!("{prefix}.mediaType"),
                    message: "must not be empty".into(),
                });
            }
            if input.bytes == 0 {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidLimit,
                    field: format!("{prefix}.bytes"),
                    message: "must be greater than zero".into(),
                });
            }
            if self
                .inputs
                .iter()
                .filter(|other| other.name == input.name)
                .count()
                > 1
                && self
                    .inputs
                    .iter()
                    .position(|other| other.name == input.name)
                    == Some(index)
            {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::DuplicateInputName,
                    field: format!("{prefix}.name"),
                    message: "is listed more than once".into(),
                });
            }
        }

        for (index, tool) in self.tools.iter().enumerate() {
            let prefix = format!("tools[{index}]");
            if !tool.alias.starts_with('/') {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidToolAlias,
                    field: format!("{prefix}.alias"),
                    message: "must be an absolute in-cell alias".into(),
                });
            }
            if !is_immutable_hash(&tool.hash) {
                problems.push(mutable_reference(&format!("{prefix}.hash")));
            }
            if tool
                .closure
                .as_ref()
                .is_some_and(|closure| !is_immutable_hash(&closure.hash))
            {
                problems.push(mutable_reference(&format!("{prefix}.closure.hash")));
            }
            if self
                .tools
                .iter()
                .filter(|other| other.alias == tool.alias)
                .count()
                > 1
                && self
                    .tools
                    .iter()
                    .position(|other| other.alias == tool.alias)
                    == Some(index)
            {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::DuplicateToolAlias,
                    field: format!("{prefix}.alias"),
                    message: "is listed more than once".into(),
                });
            }
        }

        if let Some(invocation) = &self.invocation {
            if !self.tools.iter().any(|tool| tool.alias == invocation.alias) {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::UndeclaredInvocation,
                    field: "invocation.alias".into(),
                    message: "must name exactly one declared tool alias".into(),
                });
            }
            for (index, arg) in invocation.args.iter().enumerate() {
                if arg.contains('\0') {
                    problems.push(ExecutionProblem {
                        code: ExecutionProblemCode::InvalidInvocationArgument,
                        field: format!("invocation.args[{index}]"),
                        message: "must not contain NUL".into(),
                    });
                }
            }
        }

        for (index, destination) in self.capabilities.egress.iter().enumerate() {
            if !is_named_https_destination(destination) {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidEgress,
                    field: format!("capabilities.egress[{index}]"),
                    message: "must name one HTTPS host without a path, query, or fragment".into(),
                });
            }
        }
        for (field, value) in [
            ("capabilities.timeoutMs", self.capabilities.timeout_ms),
            ("capabilities.memoryBytes", self.capabilities.memory_bytes),
            ("capabilities.outputBytes", self.capabilities.output_bytes),
        ] {
            if value == 0 {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidLimit,
                    field: field.into(),
                    message: "must be greater than zero".into(),
                });
            }
        }
        problems
    }
}

impl ExecutionReceipt {
    /// Validate a result before a control plane records or forwards it.
    pub fn problems(&self) -> Vec<ExecutionProblem> {
        let mut problems = Vec::new();
        if self.api_version != "celln.dev/v1alpha1" {
            problems.push(ExecutionProblem {
                code: ExecutionProblemCode::UnsupportedVersion,
                field: "apiVersion".into(),
                message: "must be celln.dev/v1alpha1".into(),
            });
        }
        for (field, value) in [
            ("requestId", self.request_id.as_str()),
            ("node", self.node.as_str()),
            ("cellId", self.cell_id.as_str()),
            ("startedAt", self.started_at.as_str()),
            ("completedAt", self.completed_at.as_str()),
        ] {
            if value.trim().is_empty() {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::MissingIdentity,
                    field: field.into(),
                    message: "must not be empty".into(),
                });
            }
        }
        if let Some(mote) = &self.resolved.mote {
            if !is_immutable_hash(mote) {
                problems.push(mutable_reference("resolved.mote"));
            }
        }
        for (field, hash) in self
            .resolved
            .tools
            .iter()
            .enumerate()
            .map(|(index, hash)| (format!("resolved.tools[{index}]"), hash))
            .chain(
                self.resolved
                    .inputs
                    .iter()
                    .enumerate()
                    .map(|(index, hash)| (format!("resolved.inputs[{index}]"), hash)),
            )
        {
            if !is_immutable_hash(hash) {
                problems.push(mutable_reference(&field));
            }
        }
        if let Some(output) = &self.output {
            if !is_immutable_hash(&output.hash) {
                problems.push(mutable_reference("output.hash"));
            }
            if output.media_type.trim().is_empty() {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidLimit,
                    field: "output.mediaType".into(),
                    message: "must not be empty".into(),
                });
            }
            if output.bytes == 0 {
                problems.push(ExecutionProblem {
                    code: ExecutionProblemCode::InvalidLimit,
                    field: "output.bytes".into(),
                    message: "must be greater than zero".into(),
                });
            }
        }
        problems
    }
}

fn mutable_reference(field: &str) -> ExecutionProblem {
    ExecutionProblem {
        code: ExecutionProblemCode::MutableReference,
        field: field.into(),
        message: "must be a blake3 content hash, not a name, tag, or path".into(),
    }
}

fn is_immutable_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_input_name(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_named_https_destination(value: &str) -> bool {
    let Some(host) = value.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':'))
}

/// A spec problem worth stopping for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub field: String,
    pub message: String,
    /// What to do about it. Every problem has one.
    pub fix: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}\n  fix: {}", self.field, self.message, self.fix)
    }
}

/// A non-fatal observation. Warnings never block a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub field: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not valid TOML: {source}")]
    Syntax {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("{path} has {} problem(s)", problems.len())]
    Invalid {
        path: PathBuf,
        problems: Vec<Problem>,
    },
}

impl Spec {
    /// Parse and validate a spec file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SpecError> {
        let path = path.as_ref().to_path_buf();
        let text = std::fs::read_to_string(&path).map_err(|source| SpecError::Io {
            path: path.clone(),
            source,
        })?;
        let spec: Spec = toml::from_str(&text).map_err(|source| SpecError::Syntax {
            path: path.clone(),
            source,
        })?;
        let problems = spec.problems();
        if !problems.is_empty() {
            return Err(SpecError::Invalid { path, problems });
        }
        Ok(spec)
    }

    /// Everything wrong with this spec that should stop a run.
    pub fn problems(&self) -> Vec<Problem> {
        let mut out = Vec::new();

        if self.name.trim().is_empty() {
            out.push(Problem {
                field: "name".into(),
                message: "is empty".into(),
                fix: "give the cell a name, e.g. name = \"code-reviewer\"".into(),
            });
        }

        if parse_size(&self.cell.memory).is_none() {
            out.push(Problem {
                field: "cell.memory".into(),
                message: format!("{:?} is not a size", self.cell.memory),
                fix: "use a number with a unit, e.g. \"256MiB\" or \"1GiB\"".into(),
            });
        }

        for (i, tool) in self.tools.iter().enumerate() {
            let at = format!("tool[{i}]");
            if !tool.alias.starts_with('/') {
                out.push(Problem {
                    field: format!("{at}.alias"),
                    message: format!("{:?} is not an absolute path", tool.alias),
                    fix: "aliases look like paths, e.g. \"/usr/bin/python\"".into(),
                });
            }
            if let Some(b) = &tool.builtin {
                if b != "fetch" {
                    out.push(Problem {
                        field: format!("{at}.builtin"),
                        message: format!("{b:?} is not a known capability"),
                        fix: "the only builtin is \"fetch\"".into(),
                    });
                }
                if tool.path.is_some() || tool.image.is_some() {
                    out.push(Problem {
                        field: at.clone(),
                        message: "a builtin has no path or image".into(),
                        fix: "remove path/image; a builtin is a host capability".into(),
                    });
                }
                if self.cell.allow_hosts.is_empty() {
                    out.push(Problem {
                        field: "cell.allow_hosts".into(),
                        message: "the fetch builtin needs at least one allowed host".into(),
                        fix: "set allow_hosts = [\"example.com\"]; the cell is \
                              hermetic until a host is named"
                            .into(),
                    });
                }
                continue;
            }
            match (&tool.path, &tool.image) {
                (Some(_), Some(_)) => out.push(Problem {
                    field: at.clone(),
                    message: "sets both path and image".into(),
                    fix: "a tool comes from one place: a file on this host, or \
                          an image. Remove one."
                        .into(),
                }),
                (None, None) => out.push(Problem {
                    field: at.clone(),
                    message: "has no path or image".into(),
                    fix: "set path = \"/usr/bin/…\" for a single binary, or \
                          image = \"name@sha256:…\" for a dependency closure"
                        .into(),
                }),
                (Some(p), None) => {
                    if !p.exists() {
                        out.push(Problem {
                            field: format!("{at}.path"),
                            message: format!("{} does not exist", p.display()),
                            fix: "point at a real file on this host; a tool is \
                                  bytes, and they have to come from somewhere"
                                .into(),
                        });
                    }
                }
                (None, Some(image)) => {
                    if let Err(why) = check_digest_pinned(image) {
                        out.push(Problem {
                            field: format!("{at}.image"),
                            message: why,
                            fix: "pin it with `celln image add <name:tag>`, then \
                                  use the catalogue name here; a tag can be \
                                  moved, which would change what the cell is \
                                  lent without the spec changing"
                                .into(),
                        });
                    }
                    if tool.exec.is_none() {
                        out.push(Problem {
                            field: format!("{at}.exec"),
                            message: "an image tool must say what to run".into(),
                            fix: "set exec = \"/usr/local/bin/python3.12\", a \
                                  path inside the image"
                                .into(),
                        });
                    }
                }
            }
            if tool.image.is_none() && tool.exec.is_some() {
                out.push(Problem {
                    field: format!("{at}.exec"),
                    message: "exec only applies to an image tool".into(),
                    fix: "drop exec, or set image = \"name@sha256:…\"".into(),
                });
            }
        }

        let aliases: Vec<&str> = self.tools.iter().map(|t| t.alias.as_str()).collect();
        for (i, tool) in self.tools.iter().enumerate() {
            if aliases.iter().filter(|a| **a == tool.alias).count() > 1
                && aliases.iter().position(|a| *a == tool.alias) == Some(i)
            {
                out.push(Problem {
                    field: format!("tool[{i}].alias"),
                    message: format!("{:?} is listed more than once", tool.alias),
                    fix: "one entry per alias; the later one would silently win".into(),
                });
            }
        }

        if let Some(a) = &self.agent {
            // A non-interpreter exec is legal: the model is then asked for that
            // tool's *arguments* rather than a program, which is the only way a
            // tool like curl can be driven from a task description. The trust
            // consequence is real but belongs in `warnings()`, because refusing
            // outright leaves every such tool undrivable.
            if !self.tools.iter().any(|t| t.alias == a.exec) {
                out.push(Problem {
                    field: "agent.exec".into(),
                    message: format!("{:?} is not one of the tools", a.exec),
                    fix: "point agent.exec at a declared [[tool]] — an interpreter \
                          to have the model write a program, or any other tool to \
                          have it write that tool's arguments"
                        .into(),
                });
            }
            if self.run.is_some() {
                out.push(Problem {
                    field: "agent".into(),
                    message: "a cell either declares runs or asks for one".into(),
                    fix: "remove [run]/[[run]], or remove [agent]".into(),
                });
            }
        }

        for (i, run) in self.run_list().iter().enumerate() {
            if !aliases.contains(&run.exec.as_str()) {
                out.push(Problem {
                    field: format!("run[{i}].exec"),
                    message: format!("{:?} is not one of the tools", run.exec),
                    fix: format!(
                        "add a [[tool]] with alias = {:?}, or point run.exec at one of: {}",
                        run.exec,
                        if aliases.is_empty() {
                            "(none declared)".to_string()
                        } else {
                            aliases.join(", ")
                        }
                    ),
                });
            }
        }

        out
    }

    /// Things worth saying that should not stop a run.
    pub fn warnings(&self) -> Vec<Warning> {
        let mut out = Vec::new();

        for tool in &self.tools {
            // The laundering ban only fires for interpreters, so an interpreter
            // not marked as one is a silent hole: the agent writes a script,
            // feeds it to python, and it runs with full tool-lane authority.
            if !tool.interpreter && looks_like_interpreter(&tool.alias) {
                out.push(Warning {
                    field: format!("tool {:?}", tool.alias),
                    message: "looks like an interpreter but interpreter = false. \
                              Anything it is fed will keep full tool-lane authority, \
                              including code the agent wrote. Set interpreter = true \
                              unless you mean that."
                        .into(),
                });
            }
        }

        // Asking a model for a non-interpreter's arguments is supported, but the
        // laundering ban keys off `interpreter`, so those arguments do not demote
        // the invocation the way model-written code would. Say so: the argv is
        // still agent-authored, and it runs with full tool-lane authority.
        if let Some(a) = &self.agent {
            if self
                .tools
                .iter()
                .any(|t| t.alias == a.exec && !t.interpreter)
            {
                out.push(Warning {
                    field: "agent.exec".into(),
                    message: format!(
                        "{:?} is not an interpreter, so the model writes its arguments \
                         rather than a program. Those arguments are agent-authored but \
                         do not demote the call — it runs in the tool lane. Use [run] to \
                         pin the argv yourself if that authority matters here.",
                        a.exec
                    ),
                });
            }
        }

        if self.tools.is_empty() {
            out.push(Warning {
                field: "tool".into(),
                message: "no tools declared — the cell will be able to execute nothing".into(),
            });
        }

        if self.cell.require_tier == Tier::Unsealed {
            out.push(Warning {
                field: "cell.require_tier".into(),
                message: "unsealed means no attestation is required; the cell is still \
                          hardware-isolated, but nothing carries tool-lane authority"
                    .into(),
            });
        }

        out
    }

    /// Guest memory in bytes.
    pub fn memory_bytes(&self) -> u64 {
        parse_size(&self.cell.memory).unwrap_or(256 << 20)
    }
}

/// An image reference must name immutable bytes.
fn check_digest_pinned(reference: &str) -> Result<(), String> {
    let r = reference.trim_start_matches("docker://");
    // A bare word is a catalogue name, which celln resolves to a pin it ships.
    if !r.contains('@') && !r.contains('/') && !r.contains(':') {
        return Ok(());
    }
    let Some((name, digest)) = r.split_once('@') else {
        return Err(format!("{reference:?} is a tag, not a digest"));
    };
    if name.is_empty() {
        return Err(format!("{reference:?} has no image name"));
    }
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(format!("{reference:?} must use a sha256: digest"));
    };
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{reference:?} digest is not 64 hex characters"));
    }
    Ok(())
}

/// Interpreters in practice, and the flag each takes code on.
///
/// Being on this list is what makes a tool usable with `celln agent --tool`:
/// a model writes a program, and it has to reach the interpreter somehow. A
/// compiler is not here — `go` wants a file, not a flag — and neither is a
/// language whose flag we have not confirmed.
///
/// This only ever guesses defaults. A catalogue entry that states its own
/// `language` and `code_flag` is believed over anything here.
pub fn interpreter_hint(alias: &str) -> Option<(&'static str, &'static str)> {
    let base = alias.rsplit('/').next().unwrap_or(alias);
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    Some(match base {
        "python" | "python3" => ("Python", "-c"),
        "sh" | "dash" => ("POSIX shell", "-c"),
        "bash" => ("Bash", "-c"),
        "zsh" => ("Zsh", "-c"),
        "node" | "nodejs" => ("JavaScript", "-e"),
        "deno" => ("TypeScript", "eval"),
        "bun" => ("JavaScript", "-e"),
        "ruby" => ("Ruby", "-e"),
        "perl" => ("Perl", "-e"),
        "php" => ("PHP", "-r"),
        "lua" => ("Lua", "-e"),
        "tclsh" => ("Tcl", "-c"),
        "awk" => ("Awk", "--source"),
        _ => return None,
    })
}

/// Names that are interpreters in practice. Used to warn, and to guess when
/// adding a tool to the catalogue.
pub fn looks_like_interpreter(alias: &str) -> bool {
    interpreter_hint(alias).is_some()
}

/// `256MiB`, `1GiB`, `512M`, `1073741824`.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num.parse().ok()?;
    let mult = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kib" | "kb" => 1 << 10,
        "m" | "mib" | "mb" => 1 << 20,
        "g" | "gib" | "gb" => 1 << 30,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// A starter spec, written to be read: every field is explained where it is.
pub const TEMPLATE: &str = r#"# A Celln cell spec.
#
# This describes the cell an agent runs in: how big it is, which tools it may
# be lent, and what it intends to run. Anything not listed here cannot execute
# inside the cell — that is the point of the file.
#
#   celln spec check agent.toml   # validate, and show what would happen
#   celln run agent.toml          # seal a cell and do it

name = "my-agent"

[cell]
# Guest memory. A cell's real cost is the pages it dirties, not the size it is
# given, so being generous here is cheap.
memory = "256MiB"

# The weakest tier a tool may be admitted at and still carry full authority:
#   forged   — rebuilt from source and signed  (minutes, background)
#   verified — upstream binary, pinned+scanned (seconds, the cold path)
#   unsealed — no attestation at all           (instant, never tool-lane)
require_tier = "verified"

# Each tool is lent to the cell as sealed, read-only memory. The guest can read
# and execute it and cannot modify it — not even as root, not even with its own
# page tables. Revoking it stops it in every running cell.
# Most real tools are a dependency closure - a binary plus its loader and the
# shared objects it resolves by absolute path - so they are lent as a whole
# sealed filesystem. `celln image catalogue` lists what is available;
# `celln image add <name:tag>` pins and adds anything else.
[[tool]]
alias = "/usr/bin/python"      # the name the agent uses
image = "python"               # a catalogue name, or name@sha256:...
exec  = "/usr/local/bin/python3.12"   # the path inside that image
interpreter = true             # see below

# A single *static* binary already on this host can be lent directly instead.
# It has to be static: a cell carries no loader and no libc.
#
# [[tool]]
# alias = "/usr/bin/mytool"
# path = "/usr/local/bin/mytool"

# `interpreter = true` is the most consequential line in this file. An
# interpreter fed something the agent wrote is moved to the agent lane for
# that invocation, so `python evil.py` and `python -c "..."` do not get to
# launder agent-authored code into full authority. Mark interpreters as
# interpreters.

# Let a provider write what to run. `--prompt` overrides `prompt` here.
[agent]
exec = "/usr/bin/python"
prompt = "<describe what you want it to do>"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_from(s: &str) -> Spec {
        toml::from_str(s).expect("parses")
    }

    #[test]
    fn a_recognised_interpreter_says_how_it_takes_code() {
        // `celln image add` writes these into a catalogue entry, and
        // `agent --tool` refuses any entry missing them. A name on this list
        // without a flag would add a tool that cannot then be used.
        for alias in ["/usr/bin/python3.12", "/bin/sh", "/usr/local/bin/node"] {
            let (language, flag) = interpreter_hint(alias).expect("recognised");
            assert!(!language.is_empty() && !flag.is_empty(), "{alias}");
            assert!(looks_like_interpreter(alias), "{alias}");
        }
    }

    #[test]
    fn a_compiler_is_not_an_interpreter() {
        // A model's program reaches an interpreter on a flag; `go` and `gcc`
        // want a file, so `--tool go` should fail rather than guess a flag.
        for alias in ["/usr/bin/go", "/usr/bin/gcc", "/usr/bin/curl"] {
            assert!(interpreter_hint(alias).is_none(), "{alias}");
        }
    }

    #[test]
    fn the_template_is_valid_toml_and_parses() {
        let spec: Spec = toml::from_str(TEMPLATE).expect("template parses");
        assert_eq!(spec.name, "my-agent");
        assert_eq!(spec.tools.len(), 1);
        assert!(spec.tools[0].interpreter);
        // The starter spec asks a provider for what to run rather than hard-coding
        // an invocation, so the prompt is the one blank a newcomer fills in.
        let agent = spec.agent.as_ref().expect("template declares [agent]");
        assert_eq!(agent.exec, spec.tools[0].alias);
        assert!(agent.prompt.is_some());
        assert!(
            spec.run_list().is_empty(),
            "the model supplies the run; a static one would shadow it"
        );
    }

    #[test]
    fn a_legacy_agent_task_is_read_as_a_prompt() {
        let spec = spec_from(
            "name = \"x\"\n[[tool]]\nalias = \"/p\"\npath = \"/bin/sh\"\n\
             interpreter = true\n[agent]\nexec = \"/p\"\ntask = \"hello\"\n",
        );
        assert_eq!(
            spec.agent
                .as_ref()
                .and_then(|agent| agent.prompt.as_deref()),
            Some("hello")
        );
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("256MiB"), Some(256 << 20));
        assert_eq!(parse_size("1GiB"), Some(1 << 30));
        assert_eq!(parse_size("512M"), Some(512 << 20));
        assert_eq!(parse_size("4096"), Some(4096));
        assert_eq!(parse_size("lots"), None);
        assert_eq!(parse_size("12 parsecs"), None);
    }

    #[test]
    fn a_typo_is_an_error_not_a_shrug() {
        // `teir` silently ignored would mean a cell at the wrong trust level.
        let err = toml::from_str::<Spec>("name = \"x\"\n[cell]\nteir = \"forged\"\n")
            .expect_err("unknown field must be rejected");
        assert!(err.to_string().contains("teir"), "{err}");
    }

    #[test]
    fn missing_tool_bytes_are_a_problem_with_a_fix() {
        let spec = spec_from(
            "name = \"x\"\n[[tool]]\nalias = \"/usr/bin/python\"\npath = \"/nope/absent\"\n",
        );
        let problems = spec.problems();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].field.contains("path"));
        assert!(!problems[0].fix.is_empty());
    }

    #[test]
    fn run_exec_must_name_a_declared_tool() {
        let spec = spec_from("name = \"x\"\n[run]\nexec = \"/usr/bin/ghost\"\n");
        let p = spec.problems();
        assert!(p.iter().any(|p| p.field == "run[0].exec"), "{p:?}");
        // and the fix lists what is actually available
        assert!(p.iter().any(|p| p.fix.contains("none declared")));
    }

    #[test]
    fn an_agent_block_needs_a_declared_interpreter() {
        let base = "name = \"x\"\n[[tool]]\nalias = \"/p\"\npath = \"/bin/sh\"\n";
        // not a declared tool
        let s = spec_from(&format!("{base}[agent]\nexec = \"/ghost\"\n"));
        assert!(s.problems().iter().any(|p| p.field == "agent.exec"));
        // Declared but not an interpreter is legal: the model writes that tool's
        // arguments instead of a program, which is the only way a tool like curl
        // can be driven from a task. It warns, because the argv is agent-authored
        // yet the call keeps tool-lane authority.
        let s = spec_from(&format!("{base}[agent]\nexec = \"/p\"\n"));
        assert!(!s.problems().iter().any(|p| p.field == "agent.exec"));
        assert!(s.warnings().iter().any(|w| w.field == "agent.exec"));
        // an interpreter is fine, and says nothing
        let ok = spec_from(
            "name = \"x\"\n[[tool]]\nalias = \"/p\"\npath = \"/bin/sh\"\n\
             interpreter = true\n[agent]\nexec = \"/p\"\n",
        );
        assert!(!ok.problems().iter().any(|p| p.field.starts_with("agent")));
        assert!(!ok.warnings().iter().any(|w| w.field.starts_with("agent")));
    }

    #[test]
    fn a_cell_either_declares_runs_or_asks_for_one() {
        let s = spec_from(
            "name = \"x\"\n[[tool]]\nalias = \"/p\"\npath = \"/bin/sh\"\n\
             interpreter = true\n[run]\nexec = \"/p\"\n[agent]\nexec = \"/p\"\n",
        );
        assert!(s.problems().iter().any(|p| p.field == "agent"));
    }

    #[test]
    fn a_cell_can_declare_several_runs() {
        let one = spec_from("name = \"x\"\n[run]\nexec = \"/a\"\n");
        assert_eq!(one.run_list().len(), 1);

        let many = spec_from(
            "name = \"x\"\n\
             [[run]]\nexec = \"/a\"\nargs = [\"1\"]\n\
             [[run]]\nexec = \"/b\"\ninput = \"data\"\n",
        );
        let runs = many.run_list();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].exec, "/a");
        assert_eq!(runs[0].args, ["1"]);
        assert_eq!(runs[1].input, Input::Data);

        // every invocation is checked, not just the first
        let bad = spec_from("name = \"x\"\n[[run]]\nexec = \"/ok\"\n[[run]]\nexec = \"/ghost\"\n");
        assert!(bad.problems().iter().any(|p| p.field == "run[1].exec"));
    }

    #[test]
    fn an_unmarked_interpreter_warns() {
        let spec =
            spec_from("name = \"x\"\n[[tool]]\nalias = \"/usr/bin/python3\"\npath = \"/\"\n");
        assert!(spec
            .warnings()
            .iter()
            .any(|w| w.message.contains("laundering") || w.message.contains("interpreter")));
    }

    fn spec_with(tool: &str) -> Spec {
        toml::from_str(&format!(
            "name = \"t\"\n[cell]\nmemory = \"256MiB\"\n\n[[tool]]\n{tool}\n"
        ))
        .expect("parses")
    }

    fn fields(spec: &Spec) -> Vec<String> {
        spec.problems().into_iter().map(|p| p.field).collect()
    }

    #[test]
    fn an_image_tool_must_be_digest_pinned() {
        let d = "a".repeat(64);
        let ok = spec_with(&format!(
            "alias = \"/usr/bin/python\"\nimage = \"python@sha256:{d}\"\nexec = \"/usr/local/bin/python3\""
        ));
        assert!(ok.problems().is_empty(), "{:?}", ok.problems());

        // A tag can be moved, so it cannot name what a cell is lent.
        let tagged =
            spec_with("alias = \"/usr/bin/python\"\nimage = \"python:3.12-slim\"\nexec = \"/x\"");
        assert!(fields(&tagged).iter().any(|f| f == "tool[0].image"));

        for bad in [
            "python@sha256:short",
            "python@sha512:{d}",
            "python@sha256:zz",
        ] {
            let s = spec_with(&format!("alias = \"/a\"\nimage = \"{bad}\"\nexec = \"/x\""));
            assert!(!s.problems().is_empty(), "{bad} should be refused");
        }
    }

    #[test]
    fn a_tool_names_exactly_one_source() {
        let both =
            spec_with("alias = \"/a\"\npath = \"/bin/sh\"\nimage = \"x@sha256:aa\"\nexec = \"/x\"");
        assert!(fields(&both).iter().any(|f| f == "tool[0]"));

        let neither = spec_with("alias = \"/a\"");
        assert!(fields(&neither).iter().any(|f| f == "tool[0]"));
    }

    #[test]
    fn an_image_tool_must_say_what_to_run() {
        let d = "b".repeat(64);
        let no_exec = spec_with(&format!("alias = \"/a\"\nimage = \"p@sha256:{d}\""));
        assert!(fields(&no_exec).iter().any(|f| f == "tool[0].exec"));

        let stray = spec_with("alias = \"/a\"\npath = \"/bin/sh\"\nexec = \"/x\"");
        assert!(fields(&stray).iter().any(|f| f == "tool[0].exec"));
    }

    #[test]
    fn a_real_binary_is_not_flagged_as_an_interpreter() {
        let spec = spec_from("name = \"x\"\n[[tool]]\nalias = \"/usr/bin/ls\"\npath = \"/\"\n");
        assert!(!spec
            .warnings()
            .iter()
            .any(|w| w.message.contains("interpreter")));
    }

    #[test]
    fn duplicate_aliases_are_caught_once() {
        let spec = spec_from(
            "name = \"x\"\n\
             [[tool]]\nalias = \"/a\"\npath = \"/\"\n\
             [[tool]]\nalias = \"/a\"\npath = \"/\"\n",
        );
        let dupes: Vec<_> = spec
            .problems()
            .into_iter()
            .filter(|p| p.message.contains("more than once"))
            .collect();
        assert_eq!(dupes.len(), 1, "reported once, not once per copy");
    }

    #[test]
    fn execution_request_rejects_ambient_egress() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-42",
                "workload": { "id": "review", "caller": "sympozium:default/run-42" },
                "mote": { "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                "tools": [],
                "capabilities": {
                    "workspace": "none",
                    "egress": ["https://"],
                    "timeoutMs": 30000,
                    "memoryBytes": 268435456,
                    "outputBytes": 4096
                },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request
            .problems()
            .iter()
            .any(|problem| problem.code == ExecutionProblemCode::InvalidEgress));
    }

    #[test]
    fn execution_request_accepts_only_immutable_references() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-42",
                "workload": { "id": "review", "caller": "sympozium:default/run-42" },
                "mote": { "hash": "latest" },
                "tools": [{ "alias": "/tools/review", "hash": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }],
                "capabilities": {
                    "workspace": "read-write",
                    "egress": ["https://api.example.com"],
                    "timeoutMs": 30000,
                    "memoryBytes": 268435456,
                    "outputBytes": 4096
                },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert_eq!(
            request.problems()[0].code,
            ExecutionProblemCode::MutableReference
        );
    }

    #[test]
    fn execution_request_rejects_a_mutable_ensemble_handoff() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-43",
                "workload": { "id": "review", "caller": "sympozium:default/run-43" },
                "mote": { "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                "inputs": [{
                    "name": "research-report",
                    "hash": "latest",
                    "mediaType": "text/markdown",
                    "bytes": 42
                }],
                "tools": [],
                "capabilities": {
                    "workspace": "read-only",
                    "egress": [],
                    "timeoutMs": 30000,
                    "memoryBytes": 268435456,
                    "outputBytes": 4096
                },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request.problems().iter().any(|problem| {
            problem.code == ExecutionProblemCode::MutableReference
                && problem.field == "inputs[0].hash"
        }));
    }

    #[test]
    fn invocation_must_name_one_declared_immutable_tool() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-44",
                "workload": { "id": "review", "caller": "sympozium:default/run-44" },
                "mote": { "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                "tools": [{ "alias": "/tools/review", "hash": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }],
                "invocation": { "alias": "/tools/other", "args": ["--brief"] },
                "capabilities": { "workspace": "none", "timeoutMs": 1000, "memoryBytes": 1, "outputBytes": 1 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request.problems().iter().any(|problem| {
            problem.code == ExecutionProblemCode::UndeclaredInvocation
                && problem.field == "invocation.alias"
        }));
    }

    #[test]
    fn a_valid_forge_request_has_no_problems() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-50",
                "workload": { "id": "review", "caller": "sympozium:default/run-50" },
                "forge": { "task": "print the first 100 primes" },
                "capabilities": { "workspace": "none", "timeoutMs": 30000, "memoryBytes": 268435456, "outputBytes": 4096 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request.problems().is_empty(), "{:?}", request.problems());
    }

    #[test]
    fn forge_and_mote_together_is_a_problem() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-51",
                "workload": { "id": "review", "caller": "sympozium:default/run-51" },
                "mote": { "hash": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
                "forge": { "task": "print the first 100 primes" },
                "capabilities": { "workspace": "none", "timeoutMs": 30000, "memoryBytes": 268435456, "outputBytes": 4096 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request
            .problems()
            .iter()
            .any(|problem| problem.code == ExecutionProblemCode::InvalidForge
                && problem.field == "mote"));
    }

    #[test]
    fn neither_mote_nor_forge_is_a_problem() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-52",
                "workload": { "id": "review", "caller": "sympozium:default/run-52" },
                "capabilities": { "workspace": "none", "timeoutMs": 30000, "memoryBytes": 268435456, "outputBytes": 4096 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request
            .problems()
            .iter()
            .any(|problem| problem.code == ExecutionProblemCode::InvalidForge
                && problem.field == "mote"));
    }

    #[test]
    fn forge_requires_the_agent_lane() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-53",
                "workload": { "id": "review", "caller": "sympozium:default/run-53" },
                "forge": { "task": "print the first 100 primes" },
                "capabilities": { "workspace": "none", "timeoutMs": 30000, "memoryBytes": 268435456, "outputBytes": 4096 },
                "execution": { "lane": "tool", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request.problems().iter().any(|problem| {
            problem.code == ExecutionProblemCode::InvalidForge && problem.field == "execution.lane"
        }));
    }

    #[test]
    fn forge_rejects_an_empty_task() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-54",
                "workload": { "id": "review", "caller": "sympozium:default/run-54" },
                "forge": { "task": "   " },
                "capabilities": { "workspace": "none", "timeoutMs": 30000, "memoryBytes": 268435456, "outputBytes": 4096 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request.problems().iter().any(|problem| {
            problem.code == ExecutionProblemCode::InvalidForge && problem.field == "forge.task"
        }));
    }

    #[test]
    fn forge_rejects_a_declared_invocation() {
        let request: ExecutionRequest = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "id": "sympozium-run-55",
                "workload": { "id": "review", "caller": "sympozium:default/run-55" },
                "forge": { "task": "print the first 100 primes" },
                "invocation": { "alias": "/tools/x", "args": [] },
                "capabilities": { "workspace": "none", "timeoutMs": 30000, "memoryBytes": 268435456, "outputBytes": 4096 },
                "execution": { "lane": "agent", "requireHardwareIsolation": true }
            }"#,
        )
        .expect("request parses");

        assert!(request.problems().iter().any(|problem| {
            problem.code == ExecutionProblemCode::InvalidForge && problem.field == "invocation"
        }));
    }

    #[test]
    fn a_forge_mode_receipt_with_no_mote_bundle_is_valid() {
        let receipt: ExecutionReceipt = serde_json::from_str(
            r#"{
                "apiVersion": "celln.dev/v1alpha1",
                "requestId": "sympozium-run-50",
                "phase": "succeeded",
                "node": "node-a",
                "cellId": "cell-a",
                "resolved": {
                    "tools": ["blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
                },
                "output": {
                    "hash": "blake3:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    "mediaType": "text/plain",
                    "bytes": 42
                },
                "startedAt": "2026-08-08T10:00:00Z",
                "completedAt": "2026-08-08T10:00:01Z"
            }"#,
        )
        .expect("receipt parses");

        assert!(receipt.problems().is_empty(), "{:?}", receipt.problems());
        assert!(receipt.resolved.mote.is_none());
    }

    #[test]
    fn execution_receipt_carries_only_immutable_output_and_resolved_authority() {
        let receipt: ExecutionReceipt = serde_json::from_str(include_str!(
            "../../../examples/execution/succeeded-receipt.json"
        ))
        .expect("receipt parses");

        assert!(receipt.problems().is_empty(), "{receipt:#?}");
    }

    #[test]
    fn execution_golden_examples_are_valid_contracts() {
        for example in [
            include_str!("../../../examples/execution/one-shot-agent.json"),
            include_str!("../../../examples/execution/declared-tool.json"),
            include_str!("../../../examples/execution/ensemble-handoff.json"),
            include_str!("../../../examples/execution/forge-task.json"),
        ] {
            let request: ExecutionRequest = serde_json::from_str(example).expect("example parses");
            assert!(request.problems().is_empty(), "{request:#?}");
        }
    }
}
