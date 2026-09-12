//! Small native JSON/stdin-stdout tool used by the framework package.
//! The Harness validates the exact input and output schema bytes; this binary
//! still parses a closed object instead of relying on fixture string matching.
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    text: String,
}

#[derive(Serialize)]
struct Output {
    text: String,
}

fn run() -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 4096, "uppercase input exceeds 4096 bytes");
    let input: Input = serde_json::from_slice(&bytes)?;
    let output = serde_json::to_vec(&Output {
        text: input.text.to_uppercase(),
    })?;
    anyhow::ensure!(output.len() <= 4096, "uppercase output exceeds 4096 bytes");
    std::io::stdout().write_all(&output)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("celln-uppercase: {error:#}");
        std::process::exit(1);
    }
}
