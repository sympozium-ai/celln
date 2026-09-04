//! Agent-lane guest probe: capability absence must enforce independently of seccomp.

use std::io;

const CLONE_NEWNS: i32 = 0x0002_0000;

unsafe extern "C" {
    fn unshare(flags: i32) -> i32;
}

fn main() {
    // unshare(CLONE_NEWNS) is deliberately not on pilot's seccomp denylist.
    // A root process with CAP_SYS_ADMIN would succeed; the capability-less
    // agent lane must instead reach the kernel and receive EPERM.
    let rc = unsafe { unshare(CLONE_NEWNS) };
    let error = io::Error::last_os_error();
    if rc == -1 && error.raw_os_error() == Some(1) {
        println!("CELLN_CAPABILITY_DROP_OK unshare=EPERM");
    } else {
        panic!("unshare was not capability-denied: rc={rc}, error={error}");
    }
}
