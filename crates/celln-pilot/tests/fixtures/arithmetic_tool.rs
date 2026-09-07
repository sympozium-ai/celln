//! Independently compiled, statically linked executable tool fixture.
fn main() {
    let args: Vec<i32> = std::env::args().skip(1).map(|s| s.parse().expect("integer")).collect();
    assert_eq!(args.len(), 2);
    #[cfg(add_tool)] let result = args[0].checked_add(args[1]);
    #[cfg(not(add_tool))] let result = args[0].checked_mul(args[1]);
    println!("{}", result.expect("arithmetic overflow"));
}
