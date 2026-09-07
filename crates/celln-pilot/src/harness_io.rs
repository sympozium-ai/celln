//! Bounded, concurrent pipe draining for a tool within an already sealed cell.
//! The enclosing host cell watchdog remains the final descendant/teardown bound.
use anyhow::{ensure, Context, Result};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "cannot bound child pipes"
    );
    Ok(())
}

fn drain(pipe: &mut impl Read, output: &mut Vec<u8>, limit: usize, eof: &mut bool) -> Result<()> {
    let mut bytes = [0u8; 4096];
    loop {
        match pipe.read(&mut bytes) {
            Ok(0) => {
                *eof = true;
                return Ok(());
            }
            Ok(n) => {
                ensure!(
                    n <= limit.saturating_sub(output.len()),
                    "child output exceeded limit"
                );
                output.extend_from_slice(&bytes[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

pub fn child(
    path: &str,
    args: &[String],
    input: &[u8],
    output_limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    ensure!(
        input.len() <= 65536
            && output_limit > 0
            && output_limit <= 1_048_576
            && !timeout.is_zero()
            && timeout <= Duration::from_secs(45),
        "invalid child budget"
    );
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting lent executable")?;
    let result = (|| -> Result<Vec<u8>> {
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take().context("stdout unavailable")?;
        let mut stderr = child.stderr.take().context("stderr unavailable")?;
        nonblocking(stdin.as_ref().context("stdin unavailable")?.as_raw_fd())?;
        nonblocking(stdout.as_raw_fd())?;
        nonblocking(stderr.as_raw_fd())?;
        let start = Instant::now();
        let (mut output, mut errors) = (Vec::new(), Vec::new());
        let (mut out_eof, mut err_eof, mut written) = (false, false, 0);
        loop {
            ensure!(start.elapsed() < timeout, "tool deadline exceeded");
            if let Some(pipe) = stdin.as_mut() {
                if written == input.len() {
                    stdin.take();
                } else {
                    match pipe.write(&input[written..]) {
                        Ok(0) => anyhow::bail!("tool input pipe closed"),
                        Ok(n) => written += n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            if !out_eof {
                drain(&mut stdout, &mut output, output_limit, &mut out_eof)?;
            }
            if !err_eof {
                drain(&mut stderr, &mut errors, 4096, &mut err_eof)?;
            }
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "lent executable failed");
                if out_eof && err_eof {
                    ensure!(written == input.len(), "tool exited before input delivery");
                    return Ok(output);
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_pipes_and_deadline() {
        let args = |script: &str| vec!["-c".into(), script.into()];
        assert_eq!(
            child(
                "/bin/sh",
                &args("cat"),
                br#"{"text":"borrowed"}"#,
                1024,
                Duration::from_secs(2)
            )
            .unwrap(),
            br#"{"text":"borrowed"}"#
        );
        assert!(child(
            "/bin/sh",
            &args("printf 123456"),
            b"",
            3,
            Duration::from_secs(1)
        )
        .is_err());
        assert!(child(
            "/bin/sh",
            &args("exec sleep 3"),
            b"",
            3,
            Duration::from_millis(20)
        )
        .unwrap_err()
        .to_string()
        .contains("deadline"));
        assert!(child("/bin/sh", &args("exit 7"), b"", 3, Duration::from_secs(1)).is_err());
    }
}
