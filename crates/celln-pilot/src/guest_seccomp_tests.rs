use super::install_network_seccomp;
use std::io::{self, Read};
use std::os::fd::FromRawFd;

const SECCOMP_GET_ACTION_AVAIL: libc::c_uint = 2;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

type ChildReport = [i64; 7];
const SUPPORT_ERRNO: usize = 0;
const NO_NEW_PRIVS_ERRNO: usize = 1;
const INSTALL_ERRNO: usize = 2;
const GETPID_RESULT: usize = 3;
const SOCKET_ERRNO: usize = 4;
const SOCKETPAIR_ERRNO: usize = 5;
const CONNECT_ERRNO: usize = 6;

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

unsafe fn write_report_and_exit(fd: libc::c_int, report: &ChildReport) -> ! {
    let bytes = std::slice::from_raw_parts(
        report.as_ptr().cast::<u8>(),
        std::mem::size_of::<ChildReport>(),
    );
    let mut written = 0;
    while written < bytes.len() {
        let count = libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written);
        if count > 0 {
            written += count as usize;
        } else if count < 0 && errno() == libc::EINTR {
            continue;
        } else {
            libc::_exit(2);
        }
    }
    libc::close(fd);
    libc::_exit(0)
}

unsafe fn exercise_filter(write_fd: libc::c_int) -> ! {
    let mut report: ChildReport = [0; 7];

    // This query lets the parent distinguish a genuinely unavailable seccomp
    // filter API from a malformed production filter. It does not install a
    // substitute filter: the only filter exercised below is the real one.
    let mut action = SECCOMP_RET_ERRNO | libc::EPERM as u32;
    if libc::syscall(
        libc::SYS_seccomp,
        SECCOMP_GET_ACTION_AVAIL,
        0,
        &mut action as *mut u32,
    ) != 0
    {
        report[SUPPORT_ERRNO] = errno() as i64;
    }

    // install_network_seccomp is normally called by enter_agent_lane after
    // this irreversible prerequisite. Set it in the disposable child for the
    // same unprivileged installation path used by pilot.
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        report[NO_NEW_PRIVS_ERRNO] = errno() as i64;
        write_report_and_exit(write_fd, &report);
    }
    if let Err(error) = install_network_seccomp() {
        report[INSTALL_ERRNO] = error.raw_os_error().unwrap_or(0) as i64;
        write_report_and_exit(write_fd, &report);
    }

    // Raw getpid is an allowed syscall and cannot be satisfied from a libc
    // cache. It proves the filter did not merely make the child unusable.
    report[GETPID_RESULT] = libc::syscall(libc::SYS_getpid) as i64;

    let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if socket < 0 {
        report[SOCKET_ERRNO] = errno() as i64;
    } else {
        libc::close(socket);
    }

    let mut pair = [-1; 2];
    let socketpair = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr());
    if socketpair < 0 {
        report[SOCKETPAIR_ERRNO] = errno() as i64;
    } else {
        libc::close(pair[0]);
        libc::close(pair[1]);
    }

    // Without the filter this invalid descriptor returns EBADF. EPERM proves
    // the seccomp decision happened before normal syscall argument handling.
    if libc::syscall(libc::SYS_connect, -1, std::ptr::null::<libc::sockaddr>(), 0) < 0 {
        report[CONNECT_ERRNO] = errno() as i64;
    }

    write_report_and_exit(write_fd, &report)
}

#[test]
fn actual_network_seccomp_filter_denies_network_but_allows_getpid() {
    let mut pipe_fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed: {}", io::Error::last_os_error());
    if child == 0 {
        unsafe {
            libc::close(pipe_fds[0]);
            exercise_filter(pipe_fds[1]);
        }
    }

    unsafe { libc::close(pipe_fds[1]) };
    let mut report: ChildReport = [0; 7];
    let report_bytes = unsafe {
        std::slice::from_raw_parts_mut(
            report.as_mut_ptr().cast::<u8>(),
            std::mem::size_of::<ChildReport>(),
        )
    };
    let mut reader = unsafe { std::fs::File::from_raw_fd(pipe_fds[0]) };
    reader
        .read_exact(report_bytes)
        .expect("seccomp child must return a complete report");

    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);

    assert_eq!(
        report[NO_NEW_PRIVS_ERRNO], 0,
        "PR_SET_NO_NEW_PRIVS failed with errno {}",
        report[NO_NEW_PRIVS_ERRNO]
    );
    if report[INSTALL_ERRNO] != 0 {
        let unavailable = report[INSTALL_ERRNO] == libc::ENOSYS as i64
            || (report[INSTALL_ERRNO] == libc::EINVAL as i64
                && report[SUPPORT_ERRNO] == libc::EINVAL as i64);
        if unavailable {
            eprintln!(
                "skipped: kernel seccomp filter support is unavailable (install errno {}, capability query errno {})",
                report[INSTALL_ERRNO], report[SUPPORT_ERRNO]
            );
            return;
        }
        panic!(
            "install_network_seccomp failed with errno {} (capability query errno {})",
            report[INSTALL_ERRNO], report[SUPPORT_ERRNO]
        );
    }

    assert!(
        report[GETPID_RESULT] > 0,
        "allowed getpid syscall failed after filter installation"
    );
    for (syscall, got) in [
        ("socket", report[SOCKET_ERRNO]),
        ("socketpair", report[SOCKETPAIR_ERRNO]),
        ("connect", report[CONNECT_ERRNO]),
    ] {
        assert_eq!(
            got,
            libc::EPERM as i64,
            "denied {syscall} syscall returned errno {got}, expected EPERM"
        );
    }
}
