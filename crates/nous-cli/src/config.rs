//! Small, user-owned configuration. Credentials stay with the agent CLI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Default, Deserialize, Serialize)]
struct Config {
    #[serde(default)]
    agent: Agent,
}

#[derive(Default, Deserialize, Serialize)]
struct Agent {
    default: Option<String>,
}

/// `NOUS_CONFIG` is useful for automation; otherwise follow XDG on every host.
pub fn path() -> PathBuf {
    if let Some(path) = std::env::var_os("NOUS_CONFIG") {
        return PathBuf::from(path);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("nous").join("config.toml")
}

pub fn default_agent() -> Result<Option<String>> {
    let path = path();
    if !path.exists() {
        return Ok(None);
    }
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let config: Config =
        toml::from_str(&source).with_context(|| format!("parsing config {}", path.display()))?;
    Ok(config.agent.default)
}

pub fn set_default_agent(agent: &str) -> Result<PathBuf> {
    let path = path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {}", parent.display()))?;
    }
    let config = Config {
        agent: Agent {
            default: Some(agent.to_owned()),
        },
    };
    let source = toml::to_string_pretty(&config).context("encoding nous config")?;
    std::fs::write(&path, source).with_context(|| format!("writing config {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trip_preserves_the_agent_choice() {
        let config = Config {
            agent: Agent {
                default: Some("openai".into()),
            },
        };
        let text = toml::to_string_pretty(&config).unwrap();
        let decoded: Config = toml::from_str(&text).unwrap();
        assert_eq!(decoded.agent.default.as_deref(), Some("openai"));
    }
}
