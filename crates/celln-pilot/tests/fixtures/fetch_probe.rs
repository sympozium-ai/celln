//! Host-authored probe used by `celln-fetch-proof`.
//!
//! It has no network code. Its only possible path to a response is invoking
//! `/pilot-fetch`, which exercises the guest→warden broker ABI.

use std::process::Command;

fn main() {
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
