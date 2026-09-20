//! Commands borrowed from pinned images as JSON-harness tools.
//!
//! A catalogue image may declare `commands`: ordinary command-line programs a
//! model can call through the `celln.argv/v1` binding. The packager extracts
//! each command's static executable from the image, lends it into the worker
//! closure under its own alias, and derives the JSON schema the model sees
//! from the declared parameters. Nothing here grants authority: the operator
//! still admits the package that carries these bytes.
use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// One borrowable command of a catalogue image.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogueCommand {
    /// The tool name a model calls, e.g. `grep`.
    pub name: String,
    /// Executable path inside the image; must be a static Linux amd64 ELF.
    pub exec: String,
    /// argv binding: literals, `{field}`, `{field?FLAG}` and `{field:FLAG}` entries.
    pub args: Vec<String>,
    /// Parameter fed to the program on stdin, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    pub description: String,
    #[serde(default)]
    pub params: Vec<CatalogueParam>,
}

/// One model-facing parameter; becomes a property of the tool's input schema.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogueParam {
    pub name: String,
    /// `string`, `integer` or `boolean`.
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub required: bool,
    /// Longest string or largest integer accepted.
    #[serde(default)]
    pub max: Option<u64>,
    #[serde(default)]
    pub description: String,
}

/// Alias a command is lent under inside the worker closure: its own name, so
/// every tool has a distinct path and a multi-call binary such as busybox
/// selects the applet from argv[0]. Identical bytes are hard-linked.
pub fn alias_for(command: &CatalogueCommand) -> String {
    format!("/{}", command.name)
}

/// The path inside the image a command's executable is extracted from.
pub fn validate_exec(exec: &str) -> Result<()> {
    let plain = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    };
    ensure!(
        exec.starts_with('/') && exec.len() <= 256 && exec[1..].split('/').all(plain),
        "command exec must be an absolute path of plain components: {exec}"
    );
    Ok(())
}

pub fn validate(command: &CatalogueCommand) -> Result<()> {
    ensure!(
        !command.name.is_empty()
            && command.name.len() <= 64
            && command
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "command name must be a short identifier: {:?}",
        command.name
    );
    validate_exec(&command.exec)?;
    ensure!(
        command.args.len() <= 32,
        "command {} takes at most 32 args",
        command.name
    );
    ensure!(
        !command.description.is_empty() && command.description.len() <= 512,
        "command {} needs a description of at most 512 characters",
        command.name
    );
    ensure!(
        command.params.len() <= 16,
        "command {} has too many params",
        command.name
    );
    let mut names = std::collections::BTreeSet::new();
    for param in &command.params {
        ensure!(
            !param.name.is_empty()
                && param.name.len() <= 32
                && param
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && names.insert(&param.name),
            "command {} has an invalid or duplicate param {:?}",
            command.name,
            param.name
        );
        ensure!(
            matches!(param.kind.as_str(), "string" | "integer" | "boolean"),
            "command {} param {} has unsupported type {}",
            command.name,
            param.name,
            param.kind
        );
    }
    for arg in &command.args {
        if let Some(inner) = arg.strip_prefix('{').and_then(|a| a.strip_suffix('}')) {
            let (field, switch) = match (inner.split_once('?'), inner.split_once(':')) {
                (Some((f, _)), _) => (f, true),
                (None, Some((f, _))) => (f, false),
                (None, None) => (inner, false),
            };
            let Some(param) = command.params.iter().find(|p| p.name == field) else {
                bail!("command {} arg {arg} names no param", command.name);
            };
            if switch {
                ensure!(
                    param.kind == "boolean",
                    "command {} flag {arg} needs a boolean param",
                    command.name
                );
            }
        }
    }
    if let Some(field) = &command.stdin {
        ensure!(
            command
                .params
                .iter()
                .any(|p| &p.name == field && p.kind == "string"),
            "command {} stdin must name a string param",
            command.name
        );
    }
    Ok(())
}

/// Longest string argument the tool schema subset admits.
pub const MAX_STRING_CHARS: u64 = 4096;

/// The JSON schema the model is shown for a command's arguments. The tool
/// schema subset carries no per-field descriptions, so those are folded into
/// the tool description by `description_with_params`.
pub fn input_schema(command: &CatalogueCommand) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for param in &command.params {
        let mut property = Map::new();
        property.insert("type".into(), json!(param.kind));
        match param.kind.as_str() {
            "string" => {
                property.insert("minLength".into(), json!(0));
                property.insert(
                    "maxLength".into(),
                    json!(param.max.unwrap_or(MAX_STRING_CHARS).min(MAX_STRING_CHARS)),
                );
            }
            "integer" => {
                property.insert("minimum".into(), json!(0));
                property.insert("maximum".into(), json!(param.max.unwrap_or(65536)));
            }
            _ => {}
        }
        properties.insert(param.name.clone(), Value::Object(property));
        if param.required {
            required.push(json!(param.name));
        }
    }
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

/// The tool description plus each parameter's meaning, within the 512
/// characters a description may have.
pub fn description_with_params(command: &CatalogueCommand) -> String {
    let mut text = command.description.clone();
    let notes: Vec<String> = command
        .params
        .iter()
        .filter(|p| !p.description.is_empty())
        .map(|p| format!("{}: {}", p.name, p.description))
        .collect();
    if !notes.is_empty() {
        text.push_str(" Parameters: ");
        text.push_str(&notes.join("; "));
        text.push('.');
    }
    if text.len() > 512 {
        let mut end = 509;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grep() -> CatalogueCommand {
        CatalogueCommand {
            name: "grep".into(),
            exec: "/bin/busybox".into(),
            args: vec![
                "grep".into(),
                "{ignore_case?-i}".into(),
                "-e".into(),
                "{pattern}".into(),
            ],
            stdin: Some("text".into()),
            description: "Print the lines of text matching a pattern.".into(),
            params: vec![
                CatalogueParam {
                    name: "pattern".into(),
                    kind: "string".into(),
                    required: true,
                    max: Some(512),
                    description: "regular expression".into(),
                },
                CatalogueParam {
                    name: "text".into(),
                    kind: "string".into(),
                    required: true,
                    max: Some(32768),
                    description: String::new(),
                },
                CatalogueParam {
                    name: "ignore_case".into(),
                    kind: "boolean".into(),
                    required: false,
                    max: None,
                    description: String::new(),
                },
            ],
        }
    }

    #[test]
    fn a_command_declares_a_bounded_schema_and_a_checked_binding() {
        let command = grep();
        validate(&command).unwrap();
        assert_eq!(alias_for(&command), "/grep");
        validate_exec(&command.exec).unwrap();
        let schema = input_schema(&command);
        assert_eq!(schema["properties"]["pattern"]["maxLength"], 512);
        assert_eq!(
            schema["properties"]["text"]["maxLength"], 4096,
            "clamped to the schema subset"
        );
        assert!(schema["properties"]["pattern"].get("description").is_none());
        assert!(description_with_params(&command).contains("pattern: regular expression"));
        assert_eq!(schema["properties"]["ignore_case"]["type"], "boolean");
        assert_eq!(schema["required"], json!(["pattern", "text"]));
        assert_eq!(schema["additionalProperties"], false);
        let mut bad = grep();
        bad.args.push("{nope}".into());
        assert!(validate(&bad).is_err());
        let mut bad = grep();
        bad.args[1] = "{pattern?-i}".into();
        assert!(validate(&bad).is_err(), "a flag needs a boolean");
        let mut bad = grep();
        bad.stdin = Some("ignore_case".into());
        assert!(validate(&bad).is_err(), "stdin needs a string");
        assert!(validate_exec("busybox").is_err());
        assert!(validate_exec("/bin/../sh").is_err());
    }
}
