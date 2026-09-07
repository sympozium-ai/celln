//! Bounded, non-networked guest tool for actual cancellation/deadline tests.
use std::io::Write;
fn main() {
    println!("CELLN_LIFECYCLE_STARTED");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(120));
    println!("CELLN_LIFECYCLE_UNEXPECTED_COMPLETION");
}
