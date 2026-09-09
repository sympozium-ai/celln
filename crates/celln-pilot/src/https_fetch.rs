fn main() {
    #[cfg(target_os = "linux")]
    pilot::starter_tools::main("fetch");
    #[cfg(not(target_os = "linux"))]
    panic!("Unsupported: starter tools require Linux sealed-cell execution");
}
