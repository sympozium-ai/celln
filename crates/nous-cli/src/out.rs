//! Output that behaves itself in a pipe.
//!
//! Two rules, both of them the reason this module exists rather than a pile of
//! `println!`:
//!
//! 1. **Structure when piped, prose when watched.** Attached to a terminal you
//!    get something readable. Redirected into a file or a pipe you get NDJSON,
//!    one event per line, because that is what the next program in the pipeline
//!    wants. `--json` and `--no-json` override the guess.
//! 2. **Events go to stdout, diagnostics go to stderr.** `cell run spec.toml |
//!    jq` must never have a progress message land in the JSON stream.

use is_terminal::IsTerminal;
use serde::Serialize;
use std::io::Write;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Human,
    Json,
}

pub struct Out {
    mode: Mode,
    quiet: bool,
}

/// One thing that happened. The `event` field is the stable part — callers
/// match on it — and `fields` carries whatever that event is about.
#[derive(Serialize)]
pub struct Event<'a> {
    pub event: &'a str,
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

impl Out {
    pub fn new(json: Option<bool>, quiet: bool) -> Self {
        let mode = match json {
            Some(true) => Mode::Json,
            Some(false) => Mode::Human,
            // Nobody is watching: emit something a program can read.
            None if !std::io::stdout().is_terminal() => Mode::Json,
            None => Mode::Human,
        };
        Out { mode, quiet }
    }

    pub fn is_json(&self) -> bool {
        self.mode == Mode::Json
    }

    /// An event: a line of NDJSON, or `human` if someone is watching.
    ///
    /// `--quiet` silences stdout in *both* modes. That is what quiet means
    /// elsewhere, and it is what makes `cell doctor -q || echo …` work as a
    /// pure exit-code check without a redirect.
    pub fn event(&self, event: &str, fields: serde_json::Value, human: impl AsRef<str>) {
        if self.quiet {
            return;
        }
        match self.mode {
            Mode::Json => {
                let line = serde_json::to_string(&Event { event, fields })
                    .unwrap_or_else(|e| format!(r#"{{"event":"encode_error","error":"{e}"}}"#));
                println!("{line}");
            }
            Mode::Human => {
                if !self.quiet {
                    println!("{}", human.as_ref());
                }
            }
        }
        let _ = std::io::stdout().flush();
    }

    /// Human-only decoration — headings, blank lines, summaries. Never appears
    /// in the JSON stream, so it can never corrupt a pipeline.
    pub fn say(&self, s: impl AsRef<str>) {
        if self.mode == Mode::Human && !self.quiet {
            println!("{}", s.as_ref());
        }
    }

    /// A diagnostic. Always stderr, in both modes, so it stays out of the data.
    pub fn note(&self, s: impl AsRef<str>) {
        if !self.quiet {
            eprintln!("{}", s.as_ref());
        }
    }

    pub fn warn(&self, s: impl AsRef<str>) {
        eprintln!("warning: {}", s.as_ref());
    }
}

/// Colour, but only when a terminal is going to render it.
pub fn styled(s: &str, code: &str) -> String {
    if std::io::stdout().is_terminal() {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    styled(s, "1")
}
pub fn green(s: &str) -> String {
    styled(s, "32")
}
pub fn red(s: &str) -> String {
    styled(s, "31")
}
pub fn dim(s: &str) -> String {
    styled(s, "2")
}
