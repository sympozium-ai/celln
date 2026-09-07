//! Public static test tool; deliberately tiny fixture grammar, not the Harness parser.
use std::io::Read;
fn main() {
    let mut input=String::new();
    std::io::stdin().take(1025).read_to_string(&mut input).unwrap();
    if input.contains("sleep") { std::thread::sleep(std::time::Duration::from_secs(5)); }
    if input.contains("flood") { print!("{}", "x".repeat(1024)); return; }
    if input.contains("bad-result") { print!("{{\"wrong\":true}}"); return; }
    let input: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let text=input.strip_prefix("{\"text\":\"").and_then(|s|s.strip_suffix("\"}")).expect("fixture text input");
    assert!(text.bytes().all(|c|c.is_ascii_alphabetic() || c==b'-'));
    #[cfg(uppercase_tool)]
    print!("{{\"text\":\"{}\"}}",text.to_ascii_uppercase());
    #[cfg(not(uppercase_tool))]
    print!("{{\"length\":{}}}",text.len());
}
