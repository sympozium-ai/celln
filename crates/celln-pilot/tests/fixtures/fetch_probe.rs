//! Host-authored probe used by `celln-fetch-proof`.
//!
//! It has no network code. Its only possible path to a response is invoking
//! `/pilot-fetch`, which exercises the guest→warden broker ABI.

use std::process::Command;

unsafe extern "C" {
    fn syscall(number: isize, ...) -> isize;
}

fn assert_seccomp_errno(number: isize, args: &[usize], label: &str) {
    let result = unsafe {
        match args {
            [a, b, c] => syscall(number, *a, *b, *c),
            [a, b] => syscall(number, *a, *b),
            _ => panic!("unsupported probe argument count"),
        }
    };
    assert_eq!(result, -1, "{label} unexpectedly succeeded");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(1),
        "{label} was not refused by seccomp with EPERM"
    );
}

fn main() {
    // These are fixed x86_64 Linux UAPI numbers because this probe is built
    // specifically for the static x86_64 guest. It executes after pilot has
    // installed the real agent-lane filter, so the assertions prove the guest
    // actually tried both bypass paths instead of inspecting host-side BPF.
    const SYS_SOCKET: isize = 41;
    const SYS_IO_URING_SETUP: isize = 425;
    const X32_SYSCALL_BIT: isize = 0x4000_0000;
    assert_seccomp_errno(SYS_IO_URING_SETUP, &[1, 0], "io_uring_setup");
    assert_seccomp_errno(
        SYS_SOCKET | X32_SYSCALL_BIT,
        &[2, 1, 0],
        "x32 socket",
    );
    println!("CELLN_SECCOMP_BYPASSES_DENIED io_uring=EPERM x32_socket=EPERM");

    let permissions = Command::new("/pilot-fetch")
        .arg("--prove-ioperm-scope")
        .output()
        .expect("pilot-fetch must exist in the initramfs");
    assert!(
        permissions.status.success(),
        "pilot-fetch I/O permission proof failed: {}",
        String::from_utf8_lossy(&permissions.stderr)
    );
    let permission_report = String::from_utf8_lossy(&permissions.stdout);
    assert!(
        permission_report.contains(
            "CELLN_FETCH_IOPERM_OK ports=0x500-0x502 denied=0x503:SIGSEGV"
        ),
        "pilot-fetch did not prove its I/O permission scope"
    );
    print!("{permission_report}");

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com/".into());
    let result = Command::new("/pilot-fetch")
        .arg(url)
        .output()
        .expect("pilot-fetch must exist in the initramfs");
    assert!(
        result.status.success(),
        "pilot-fetch failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!result.stdout.is_empty(), "broker returned an empty response");
    println!("CELLN_FETCH_OK bytes={}", result.stdout.len());
}
