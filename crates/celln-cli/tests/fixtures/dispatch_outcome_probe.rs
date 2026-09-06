use std::io::{self, Write};

unsafe extern "C" {
    fn unshare(flags: i32) -> i32;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("silent") => {}
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
