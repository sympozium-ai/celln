//! Native schema-bound JSON/stdin-stdout adapter; no arbitrary OCI compatibility.
#[cfg(target_os = "linux")]
fn run() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use celln_manifest::Hash;
    use std::io::Read;
    let raw = std::env::args()
        .nth(1)
        .context("missing host configuration")?;
    ensure!(raw.len() <= 65536, "configuration exceeds delivery limit");
    let config: pilot::json_harness::Config = serde_json::from_str(&raw)?;
    pilot::json_harness::validate(&config)?;
    // The host must deliver this runtime and all lent executables as a signed
    // sealed closure. These checks are fail-closed diagnostics, not a substitute
    // for the host's hardware sealing or grant verification.
    for tool in &config.tools {
        let mut options = std::fs::OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt;
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(&tool.path)?;
        ensure!(file.metadata()?.is_file(), "tool is not a regular file");
        let mut bytes = Vec::new();
        file.take(536870913).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 536870912 && Hash::of(&bytes).0 == tool.hash,
            "lent executable identity mismatch"
        );
        ensure!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&tool.path)
                .is_err(),
            "lent executable is writable"
        );
    }
    pilot::json_harness::run(
        &config,
        |wire| {
            pilot::harness_io::child(
                "/pilot-fetch",
                &["--json-stdin".into()],
                wire,
                1_048_576,
                std::time::Duration::from_secs(45),
            )
        },
        |tool, input| {
            pilot::harness_io::child(
                &tool.path,
                &[],
                input,
                tool.output_bytes,
                std::time::Duration::from_millis(tool.timeout_ms),
            )
        },
        |event| println!("CELLN_HARNESS_EVENT {event}"),
    )?;
    Ok(())
}

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = run() {
        eprintln!("CELLN_HARNESS_ERROR {error:#}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Unsupported: JSON-tool adapter requires Linux sealed-cell execution");
        std::process::exit(5);
    }
}
