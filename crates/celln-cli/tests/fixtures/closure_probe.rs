use std::{fs, io::Write, process::Command};
use std::os::fd::AsRawFd;
extern "C" {
    fn mmap(addr: *mut std::ffi::c_void, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut std::ffi::c_void;
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "none".into());
    let library = std::env::args().nth(2).expect("library path");
    if mode == "revoke" {
        println!("closure-revoke-ready");
        loop { std::thread::sleep(std::time::Duration::from_millis(1)); }
    }
    let before = fs::read(&library).expect("admitted library readable");
    assert!(fs::OpenOptions::new().write(true).open(&library).is_err());
    assert!(fs::remove_file(&library).is_err());
    assert!(fs::rename(&library, "/tmp/stolen.so").is_err());
    assert!(fs::read("/etc/closure-unlisted").is_err());
    assert!(fs::read("/celln/manifest.json").is_err());
    if mode == "read-write" {
        let mut scratch = fs::File::create("/tmp/data").unwrap();
        scratch.write_all(b"private scratch").unwrap();
        fs::copy("/bin/program", "/tmp/copied").unwrap();
        assert!(Command::new("/tmp/copied").status().is_err());
        assert!(fs::rename("/tmp/copied", &library).is_err());
        assert!(fs::hard_link(&library, "/tmp/library.so").is_err());
        fs::copy(&library, "/tmp/library.so").unwrap();
        let copied = fs::File::open("/tmp/library.so").unwrap();
        // Landlock EXECUTE alone does not cover dlopen/mmap(PROT_EXEC).
        // The host-selected noexec scratch mount must stop that alternate path.
        let mapping = unsafe { mmap(std::ptr::null_mut(), 4096, 1 | 4, 2, copied.as_raw_fd(), 0) };
        assert_eq!(mapping as isize, -1, "mutable library executable mapping permitted");
    } else {
        assert!(fs::write("/tmp/data", b"denied").is_err());
    }
    assert_eq!(before, fs::read(&library).unwrap());
    println!("closure:{mode}:dynamic-loader:replacement-denied");
}
