//! Explicit local proof helper: never execute/source a shell startup file.
use anyhow::{ensure, Context, Result};
use std::{
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
pub struct Credential {
    pub path: PathBuf,
}
impl Drop for Credential {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
pub fn from_zshrc(path: &Path) -> Result<Credential> {
    let mut input = String::new();
    std::fs::File::open(path)?
        .take(1_048_577)
        .read_to_string(&mut input)?;
    ensure!(input.len() <= 1_048_576, "startup file too large");
    let values: Vec<&str> = input
        .lines()
        .filter_map(|line| {
            let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
            line.strip_prefix("DEEPSEEK_API_KEY=")
        })
        .collect();
    ensure!(
        values.len() == 1,
        "expected one literal DeepSeek key assignment"
    );
    let raw = values[0].trim();
    let value = raw
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(raw);
    ensure!(
        (16..=512).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "key must be a literal token"
    );
    let path = std::env::temp_dir().join(format!(
        "celln-proof-key-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    let credential = Credential { path };
    file.write_all(value.as_bytes())
        .context("could not write private proof credential")?;
    Ok(credential)
}
