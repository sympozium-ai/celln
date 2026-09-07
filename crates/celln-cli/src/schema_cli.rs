//! Offline, bounded schema/data checks. No store writes or execution authority.
use anyhow::Result;
use celln_manifest::{
    tool_schema::{ToolSchema, MAX_SCHEMA_BYTES, MAX_VALUE_BYTES, PROFILE},
    Hash,
};
use std::{io::Read, path::Path};

fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "schema or value exceeds byte ceiling");
    Ok(bytes)
}

pub fn verify(
    path: &Path,
    expected: &str,
    value: Option<&Path>,
    max_value_bytes: Option<usize>,
) -> Result<u8> {
    let schema = ToolSchema::parse(&read(path, MAX_SCHEMA_BYTES)?, &Hash(expected.into()))
        .map_err(anyhow::Error::msg)?;
    match (value, max_value_bytes) {
        (Some(path), Some(limit)) if (1..=MAX_VALUE_BYTES).contains(&limit) => {
            schema
                .validate(&read(path, limit)?, limit)
                .map_err(anyhow::Error::msg)?;
        }
        (None, None) => {}
        _ => anyhow::bail!("value validation requires an explicit 1..65536 byte ceiling"),
    }
    println!(
        "{}",
        serde_json::json!({
            "apiVersion":"celln.dev/tool-schema-verification-v1",
            "profile":PROFILE,
            "schema":schema.identity().0,
            "valueValidated":value.is_some(),
            "scope":"schema-and-data-only"
        })
    );
    Ok(0)
}
