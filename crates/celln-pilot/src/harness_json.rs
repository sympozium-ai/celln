//! Existing one-shot entry point: no retained context accepted here.
fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = pilot::json_guest::run(&[], None) {
        eprintln!("CELLN_HARNESS_ERROR {error:#}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Unsupported: JSON-tool adapter requires Linux sealed-cell execution");
        std::process::exit(5);
    }
}
