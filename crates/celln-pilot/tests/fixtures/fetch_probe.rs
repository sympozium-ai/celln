//! Host-authored probe used by `celln-fetch-proof`.
//!
//! It has no network code. Its only possible path to a response is invoking
//! `/pilot-fetch`, which exercises the guest→warden broker ABI.

use std::process::Command;

fn main() {
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
