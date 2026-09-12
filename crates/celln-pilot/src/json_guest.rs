//! Native schema-bound JSON/stdin-stdout adapter; no arbitrary OCI compatibility.
#[cfg(target_os = "linux")]
pub fn run_entry() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use std::io::Write;
    let raw = std::env::args()
        .nth(1)
        .context("missing host configuration")?;
    ensure!(raw.len() <= 65536, "configuration exceeds delivery limit");
    let header: serde_json::Value = serde_json::from_str(&raw)?;
    if header["contract"] != crate::json_harness::DIRECT_CONTRACT {
        return run(&[], None);
    }
    let config: crate::json_harness::DirectConfig = serde_json::from_str(&raw)?;
    crate::json_harness::validate_direct(&config)?;
    check_lent_tools(std::slice::from_ref(&config.tool))?;
    let output = crate::json_harness::run_direct(&config, |tool, input| {
        crate::harness_io::child(
            &tool.path,
            &[],
            input,
            tool.output_bytes,
            std::time::Duration::from_millis(tool.timeout_ms),
        )
    })?;
    std::io::stdout().write_all(&output)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn check_lent_tools(tools: &[crate::json_harness::Tool]) -> anyhow::Result<()> {
    use anyhow::ensure;
    use celln_manifest::Hash;
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    // Diagnostics only: host publisher, sealing and execution-grant checks
    // remain mandatory. File identity alone is not executable authority.
    for tool in tools {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&tool.path)?;
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
    Ok(())
}
#[cfg(target_os = "linux")]
pub fn run(
    history: &[crate::json_harness::Exchange],
    expected_task: Option<&str>,
) -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    let raw = std::env::args()
        .nth(1)
        .context("missing host configuration")?;
    ensure!(raw.len() <= 65536, "configuration exceeds delivery limit");
    let config: crate::json_harness::Config = serde_json::from_str(&raw)?;
    ensure!(
        expected_task.map_or(true, |task| task == config.task),
        "worker task/context mismatch"
    );
    crate::json_harness::validate(&config)?;
    check_lent_tools(&config.tools)?;
    crate::json_harness::run_with_history(
        &config,
        history,
        |wire| {
            crate::harness_io::child(
                "/pilot-fetch",
                &["--json-stdin".into()],
                wire,
                1_048_576,
                std::time::Duration::from_secs(45),
            )
        },
        |tool, input| {
            crate::harness_io::child(
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
