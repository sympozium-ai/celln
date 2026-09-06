//! Agent-lane guest probe: capability absence must enforce independently of seccomp.

use std::io;

const CLONE_NEWNS: i32 = 0x0002_0000;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const SYS_CAPGET: i64 = 125;
const PR_CAPBSET_READ: i32 = 23;
const PR_CAP_AMBIENT: i32 = 47;
const PR_CAP_AMBIENT_IS_SET: u64 = 1;

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

unsafe extern "C" {
    fn unshare(flags: i32) -> i32;
    fn syscall(number: i64, ...) -> i64;
    fn prctl(option: i32, ...) -> i32;
}

fn main() {
    let header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut sets = [
        CapUserData {
            effective: u32::MAX,
            permitted: u32::MAX,
            inheritable: u32::MAX,
        };
        2
    ];
    let capget = unsafe { syscall(SYS_CAPGET, &header, sets.as_mut_ptr()) };
    assert_eq!(capget, 0, "capget failed: {}", io::Error::last_os_error());
    assert!(
        sets.iter().all(|set| set.effective == 0 && set.permitted == 0 && set.inheritable == 0),
        "agent retained effective, permitted, or inheritable capabilities"
    );
    for capability in 0_u64..64 {
        let bounded = unsafe { prctl(PR_CAPBSET_READ, capability, 0, 0, 0) };
        if bounded < 0 && io::Error::last_os_error().raw_os_error() == Some(22) {
            continue;
        }
        assert_eq!(bounded, 0, "capability {capability} remains in bounding set");
        let ambient = unsafe {
            prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_IS_SET,
                capability,
                0,
                0,
            )
        };
        assert_eq!(ambient, 0, "capability {capability} remains ambient");
    }

    // unshare(CLONE_NEWNS) is deliberately not on pilot's seccomp denylist.
    // A root process with CAP_SYS_ADMIN would succeed; the capability-less
    // agent lane must instead reach the kernel and receive EPERM.
    let rc = unsafe { unshare(CLONE_NEWNS) };
    let error = io::Error::last_os_error();
    if rc == -1 && error.raw_os_error() == Some(1) {
        println!("CELLN_CAPABILITY_DROP_OK sets=empty bounding=empty unshare=EPERM");
    } else {
        panic!("unshare was not capability-denied: rc={rc}, error={error}");
    }
}
