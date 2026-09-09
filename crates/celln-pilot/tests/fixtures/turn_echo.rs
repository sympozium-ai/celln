//! Deterministic worker fixture, not an LLM or a Harness emulator.
fn main() {
    let task = std::env::args().nth(1).expect("one task argument required");
    assert!(task.len() <= 2048);
    if task.contains("block-child") {
        use std::io::Write;
        println!("CHILD_BUSY_ENTERED");
        std::io::stdout().flush().unwrap();
        loop {
            std::hint::spin_loop();
        }
    }
    print!("{task}");
}
