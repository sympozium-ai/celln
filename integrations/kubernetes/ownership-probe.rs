//! Storage qualification helper, not an execution or hardware-isolation proof.
//! Run on the same mounted test directory from separate Kubernetes nodes.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: ownership-probe hold|contend|publish|read DIRECTORY".into());
    }
    let dir = PathBuf::from(&args[2]);
    fs::create_dir_all(&dir)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("probe.lock"))?;
    let result = unsafe { flock(lock.as_raw_fd(), 2 | 4) }; // LOCK_EX | LOCK_NB
    if args[1] == "contend" {
        if result == 0 {
            return Err("cross-node lock was NOT exclusive".into());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error.into());
        }
        println!("PASS: competing node observed WouldBlock");
        return Ok(());
    }
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    match args[1].as_str() {
        "hold" => {
            println!("LOCK_HELD");
            std::io::stdout().flush()?;
            // Bounded hold; killing this process must also release the lock.
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        "publish" => {
            let staging = dir.join("probe-staging");
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&staging)?;
            file.write_all(b"celln ownership publication v1\n")?;
            file.sync_all()?;
            // Atomic no-clobber publication, as required by persist_noclobber.
            fs::hard_link(&staging, dir.join("probe-record"))?;
            File::open(&dir)?.sync_all()?;
            println!("PASS: record published and directory synced");
        }
        "read" => {
            let mut bytes = Vec::new();
            File::open(dir.join("probe-record"))?
                .take(4096)
                .read_to_end(&mut bytes)?;
            if bytes != b"celln ownership publication v1\n" {
                return Err("record mismatch".into());
            }
            File::open(&dir)?.sync_all()?;
            println!("PASS: exclusive lock reacquired; published record visible");
        }
        _ => return Err("unknown operation".into()),
    }
    Ok(())
}
