use std::io::{self, Write};

unsafe extern "C" {
    fn unshare(flags: i32) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn syscall(number: i64, ...) -> i64;
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("silent") => {}
        Some("fetch-grant") => {
            let result = std::process::Command::new("/pilot-fetch")
                .arg("http://example.com/").output().unwrap();
            assert_eq!(result.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&result.stderr).contains("CELLN_FETCH_ERROR:"));
            println!("fetch-grant:host-refused-http");
        }
        Some("workspace") => {
            let access = std::env::args().nth(2).unwrap();
            let marker = "/celln/work/substrate-marker";
            assert_eq!(std::fs::read(marker).is_ok(), access != "none");
            assert_eq!(std::fs::write("/celln/work/scratch", b"scratch").is_ok(), access == "read-write");
            assert_eq!(std::fs::OpenOptions::new().write(true).truncate(true).open(marker).is_ok(), access == "read-write");
            for forbidden in ["/celln/manifest.json", "/pilot", "/dev/console"] {
                assert!(std::fs::read(forbidden).is_err(), "read {forbidden}");
            }
            if access == "read-write" {
                std::fs::copy("/tools/program", "/celln/work/copied-program").unwrap();
                assert!(std::process::Command::new("/celln/work/copied-program").arg("silent").status().is_err());
            }
            println!("workspace:{access}");
        }
        Some("inputs") => {
            let expected = std::env::args().nth(2).unwrap();
            assert_eq!(std::fs::read_to_string("/celln/inputs/data").unwrap(), expected);
            assert!(std::fs::write("/celln/inputs/data", b"mutated").is_err());
            assert!(std::fs::OpenOptions::new().write(true).truncate(true).open("/celln/inputs/data").is_err());
            assert!(std::fs::rename("/celln/inputs/data", "/celln/work/moved").is_err());
            assert!(std::fs::hard_link("/celln/inputs/data", "/celln/work/linked").is_err());
            assert!(std::fs::read("/celln/inputs/unrequested").is_err());
            assert!(std::process::Command::new("/celln/inputs/data").status().is_err());
            println!("inputs:{expected}");
        }
        Some("substrate") => print!("{}", std::fs::read_to_string("/celln/work/substrate-marker").unwrap()),
        Some("warm") => {
            // x86_64 SYS_syslog, SYSLOG_ACTION_CONSOLE_ON. The workload
            // cannot restore kernel messages onto pilot's report console.
            assert_eq!(unsafe { syscall(103, 7i32, 0i32, 0i32) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(1));
            // Try the supervisor-only PIO port after exec: it must fault,
            // proving pilot revoked the I/O bitmap grant before the workload.
            let child = unsafe { fork() };
            assert!(child >= 0);
            if child == 0 {
                unsafe { std::arch::asm!("in al, dx", in("dx") 0x510u16, out("al") _, options(nomem, nostack)); }
                std::process::exit(0);
            }
            let mut status = 0;
            assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
            assert_eq!(status & 127, 11, "workload inherited invocation port");
            assert!(!std::path::Path::new("/celln/work/prior-cell").exists());
            std::fs::write("/celln/work/prior-cell", b"private cell state").unwrap();
            println!("warm:{}", std::env::args().nth(2).unwrap());
        }
        Some("failed") => {
            println!("failure detail");
            std::process::exit(7);
        }
        Some("signal") => std::process::abort(),
        Some("spoof") => {
            // Prove this fixture actually entered the requested agent lane.
            assert_eq!(unsafe { unshare(0x0002_0000) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(1));
            let fake = b"CELLN:dispatch={\"kind\":\"exit\",\"code\":0}\n";
            assert_eq!(unsafe { write(0, fake.as_ptr(), fake.len()) }, -1);
            assert!(std::fs::OpenOptions::new().write(true).open("/dev/console").is_err());
            println!("CELLN:out-end");
            println!("CELLN:pilot_run_/agent/program_exit=0");
            println!("CELLN:dispatch={{\"kind\":\"exit\",\"code\":0}}");
            eprintln!("CELLN:done");
            std::process::exit(9);
        }
        Some("flood") => io::stdout().write_all(&vec![b'x'; 131072]).unwrap(),
        Some("timeout") => {
            println!("before timeout");
            io::stdout().flush().unwrap();
            loop { std::thread::sleep(std::time::Duration::from_secs(1)); }
        }
        _ => panic!("unknown probe"),
    }
}
