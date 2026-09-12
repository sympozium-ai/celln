//! Drain bounded output without reader threads that can outlive a child. On
//! Linux each subprocess gets its own process group, terminated before reaping
//! the leader so its PID cannot be recycled under the cleanup operation.

use std::io;
use std::process::{Command, Output};

pub fn output(command: &mut Command) -> io::Result<Output> {
    output_with_timeout(command, None)
}

pub fn output_with_timeout(
    command: &mut Command,
    limit: Option<std::time::Duration>,
) -> io::Result<Output> {
    crate::check()?;
    #[cfg(target_os = "linux")]
    {
        unix_output(command, limit, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if crate::current().is_some() || limit.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "controlled process groups require Linux",
            ));
        }
        command.output()
    }
}

/// Feed bounded private input over an anonymous pipe, while continuing to poll
/// cancellation and drain output. No input is put in argv, environment or files.
#[cfg(target_os = "linux")]
pub fn output_with_input(
    command: &mut Command,
    input: &[u8],
    limit: std::time::Duration,
) -> io::Result<Output> {
    if input.len() > 2 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "subprocess input exceeded 2 MiB",
        ));
    }
    crate::check()?;
    unix_output(command, Some(limit), Some(input))
}

#[cfg(target_os = "linux")]
fn unix_output(
    command: &mut Command,
    limit: Option<std::time::Duration>,
    input: Option<&[u8]>,
) -> io::Result<Output> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Stdio};
    use std::time::Duration;
    struct Owned(Child, bool);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.1 {
                return;
            }
            // The leader has not been reaped, so this is still our PGID.
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.kill(); // also stop a leader that changed its group
            let _ = self.0.wait();
        }
    }
    fn nonblocking(fd: i32) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn drain(reader: &mut impl Read, dest: &mut Vec<u8>) -> io::Result<bool> {
        let mut buf = [0; 8192];
        // Bound each pass as well as total capture so a flooding child cannot
        // starve cancellation polling.
        for _ in 0..32 {
            match reader.read(&mut buf) {
                Ok(0) => return Ok(true),
                Ok(n) => {
                    if dest.len() + n > 8 * 1024 * 1024 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "subprocess output exceeded 8 MiB",
                        ));
                    }
                    dest.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(true),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }
    command
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = Owned(command.spawn()?, true);
    let started = std::time::Instant::now();
    let mut stdin = child.0.stdin.take();
    if let Some(writer) = stdin.as_ref() {
        nonblocking(writer.as_raw_fd())?;
    }
    let input = input.unwrap_or_default();
    let mut written = 0;
    let mut stdout = child.0.stdout.take().expect("piped stdout");
    let mut stderr = child.0.stderr.take().expect("piped stderr");
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    loop {
        crate::check()?;
        if limit.is_some_and(|limit| started.elapsed() >= limit) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "subprocess deadline exceeded",
            ));
        }
        if let Some(writer) = stdin.as_mut() {
            if written < input.len() {
                let end = (written + 8192).min(input.len());
                match writer.write(&input[written..end]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "subprocess input closed",
                        ))
                    }
                    Ok(n) => written += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
            if written == input.len() {
                stdin.take();
            }
        }
        drain(&mut stdout, &mut out)?;
        drain(&mut stderr, &mut err)?;
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child.0.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { info.si_pid() } != 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Stop background children even when the leader finished normally.
    unsafe {
        libc::kill(-(child.0.id() as i32), libc::SIGKILL);
    }
    while !drain(&mut stdout, &mut out)? {
        crate::check()?;
    }
    while !drain(&mut stderr, &mut err)? {
        crate::check()?;
    }
    let status = child.0.wait()?;
    // Reaped already; do not signal a now-reusable PGID in Drop.
    child.1 = false;
    crate::check()?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn private_input_is_drained_without_pipe_deadlock() {
        let input = vec![b'x'; 512 * 1024];
        let out =
            output_with_input(&mut Command::new("cat"), &input, Duration::from_secs(5)).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, input);
    }

    #[test]
    fn blocked_private_input_obeys_cancellation() {
        let control = crate::Control::new(Duration::from_millis(80)).unwrap();
        let started = Instant::now();
        let result = control.scope(|| {
            output_with_input(
                Command::new("sleep").arg("30"),
                &vec![b'x'; 512 * 1024],
                Duration::from_secs(30),
            )
        });
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    fn not_running(pid: &str) -> bool {
        std::fs::read_to_string(format!("/proc/{}/stat", pid.trim()))
            .map(|s| s.split_once(") ").unwrap().1.starts_with('Z'))
            .unwrap_or(true)
    }

    #[test]
    fn deadline_terminates_owned_descendants_and_reaps_leader() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let c = crate::Control::new(Duration::from_millis(150)).unwrap();
        let started = Instant::now();
        let result = c.scope(|| {
            output(
                Command::new("sh")
                    .args(["-c", "sleep 60 & echo $! > \"$1\"; wait", "test"])
                    .arg(&pidfile),
            )
        });
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        let pid = std::fs::read_to_string(pidfile).unwrap();
        for _ in 0..100 {
            if not_running(&pid) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("descendant remained running");
    }

    #[test]
    fn successful_leader_cannot_leave_a_pipe_holding_background_process() {
        let started = Instant::now();
        let result = output(Command::new("sh").args(["-c", "sleep 60 & printf done"])).unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"done");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn cancellation_stops_a_process_before_its_command_deadline() {
        let c = crate::Control::new(Duration::from_secs(60)).unwrap();
        let cancel = c.clone();
        let worker =
            std::thread::spawn(move || c.scope(|| output(Command::new("sleep").arg("60"))));
        cancel.cancel();
        assert!(worker.join().unwrap().is_err());
    }
}
