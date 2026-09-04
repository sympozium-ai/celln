//! Small, user-owned configuration. Credentials stay with the provider CLI.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

/// Written as `[provider]`. `[agent]` is the name this had before providers
/// were distinguished from the agent lane, and is still read so an existing
/// config keeps working; whichever is present wins, `[provider]` first.
#[derive(Default, Deserialize, Serialize)]
struct Config {
    #[serde(default)]
    provider: Provider,
    #[serde(default, skip_serializing_if = "Provider::is_empty")]
    agent: Provider,
}

#[derive(Default, Deserialize, Serialize)]
struct Provider {
    default: Option<String>,
}

impl Provider {
    fn is_empty(&self) -> bool {
        self.default.is_none()
    }
}

/// `CELLN_CONFIG` is useful for automation; otherwise follow XDG on every host.
pub fn path() -> PathBuf {
    if let Some(path) = std::env::var_os("CELLN_CONFIG") {
        return PathBuf::from(path);
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("celln").join("config.toml")
}

fn legacy_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CELL_CONFIG") {
        return Some(PathBuf::from(path));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("cell").join("config.toml"))
}

pub fn default_agent() -> Result<Option<String>> {
    let path = path();
    let path = if path.exists() {
        path
    } else {
        legacy_path()
            .filter(|legacy| legacy.exists())
            .unwrap_or(path)
    };
    if !path.exists() {
        return Ok(None);
    }
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let config: Config =
        toml::from_str(&source).with_context(|| format!("parsing config {}", path.display()))?;
    Ok(config.provider.default.or(config.agent.default))
}

pub fn set_default_agent(agent: &str) -> Result<PathBuf> {
    let path = path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating config directory {}", parent.display()))?;
    }
    let config = Config {
        provider: Provider {
            default: Some(agent.to_owned()),
        },
        agent: Provider::default(),
    };
    let source = toml::to_string_pretty(&config).context("encoding celln config")?;
    write_private(&path, source.as_bytes())
        .with_context(|| format!("writing config {}", path.display()))?;
    Ok(path)
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;

    // `mode` applies only when open creates the file, and is still filtered by
    // umask. Tighten an existing file before replacing its contents, then set
    // the exact final mode so even an unusually restrictive umask cannot alter
    // this config's contract.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.set_len(0)?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chosen(text: &str) -> Option<String> {
        let config: Config = toml::from_str(text).unwrap();
        config.provider.default.or(config.agent.default)
    }

    #[test]
    fn config_round_trip_preserves_the_provider_choice() {
        let config = Config {
            provider: Provider {
                default: Some("openai".into()),
            },
            agent: Provider::default(),
        };
        let text = toml::to_string_pretty(&config).unwrap();
        assert!(text.contains("[provider]"), "{text}");
        assert!(!text.contains("[agent]"), "{text}");
        assert_eq!(chosen(&text).as_deref(), Some("openai"));
    }

    #[test]
    fn a_config_written_before_the_rename_still_selects_its_provider() {
        // Anyone who ran `celln setup` on 0.5.4 or earlier has this on disk.
        assert_eq!(
            chosen("[agent]\ndefault = \"anthropic\"\n").as_deref(),
            Some("anthropic")
        );
    }

    #[test]
    fn provider_wins_when_a_config_carries_both() {
        assert_eq!(
            chosen("[provider]\ndefault = \"local\"\n[agent]\ndefault = \"openai\"\n").as_deref(),
            Some("local")
        );
    }
}
