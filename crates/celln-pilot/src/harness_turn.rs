//! Separate turn-worker artifact. Host config controls model, tools and persona.
#[cfg(target_os = "linux")]
fn run() -> anyhow::Result<()> {
    use anyhow::Context;
    let raw = std::env::args().nth(2).context("missing parent context")?;
    let context = pilot::turn_worker::ContextInput::decode(&raw)?;
    pilot::json_guest::run(&context.history, Some(&context.message))
}
fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = run() {
        eprintln!("CELLN_HARNESS_ERROR {error:#}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Unsupported: native turn worker requires Linux");
        std::process::exit(5);
    }
}
