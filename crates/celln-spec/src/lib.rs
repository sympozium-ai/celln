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

    #[serde(default)]
    pub run: Option<Run>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    #[serde(default = "default_memory")]
    pub memory: String,

    #[serde(default = "default_tier")]
    pub require_tier: Tier,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            memory: default_memory(),
            require_tier: default_tier(),
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

    /// Where the bytes come from on this host.
    pub path: PathBuf,

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
            if !tool.path.exists() {
                out.push(Problem {
                    field: format!("{at}.path"),
                    message: format!("{} does not exist", tool.path.display()),
                    fix: "point at a real file on this host; a tool is bytes, and \
                          they have to come from somewhere"
                        .into(),
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

        if let Some(run) = &self.run {
            if !aliases.contains(&run.exec.as_str()) {
                out.push(Problem {
                    field: "run.exec".into(),
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

/// Names that are interpreters in practice. Used only to warn.
fn looks_like_interpreter(alias: &str) -> bool {
    let base = alias.rsplit('/').next().unwrap_or(alias);
    let base = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    matches!(
        base,
        "python"
            | "python3"
            | "sh"
            | "bash"
            | "zsh"
            | "dash"
            | "node"
            | "nodejs"
            | "ruby"
            | "perl"
            | "lua"
            | "php"
            | "deno"
            | "bun"
            | "awk"
            | "tclsh"
    )
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
[[tool]]
alias = "/usr/bin/python"      # the name the agent uses
path = "/usr/bin/python3"      # where the bytes come from on this host
interpreter = true             # see below

# `interpreter = true` is the most consequential line in this file. An
# interpreter fed something the agent wrote is moved to the agent lane for
# that invocation, so `python evil.py` and `python -c "..."` do not get to
# launder agent-authored code into full authority. Mark interpreters as
# interpreters.

[run]
exec = "/usr/bin/python"
args = ["review.py"]
# Where the input came from:
#   none — nothing interpreted
#   tool — came in through the attestation gate
#   data — the agent wrote it  (demotes an interpreter)
input = "data"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_from(s: &str) -> Spec {
        toml::from_str(s).expect("parses")
    }

    #[test]
    fn the_template_is_valid_toml_and_parses() {
        let spec: Spec = toml::from_str(TEMPLATE).expect("template parses");
        assert_eq!(spec.name, "my-agent");
        assert_eq!(spec.tools.len(), 1);
        assert!(spec.tools[0].interpreter);
        assert_eq!(spec.run.unwrap().input, Input::Data);
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
        assert!(p.iter().any(|p| p.field == "run.exec"), "{p:?}");
        // and the fix lists what is actually available
        assert!(p.iter().any(|p| p.fix.contains("none declared")));
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
}
