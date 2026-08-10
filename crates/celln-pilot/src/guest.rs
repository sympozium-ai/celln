//! `celln-pilot` — pilot, running **inside the cell**.
//!
//! Everything else in this crate is a library the host links against. This is
//! the binary that runs in the guest, and it is the first piece of pilot to do
//! so. Built statically against musl so it needs nothing from the guest
//! filesystem: the initramfs carries this one file and a manifest.
//!
//! What it does today, which is the whole of pilot's security-critical job:
//!
//!   1. Read the signed manifest the host staged in the cell.
//!   2. For each thing it is asked to run, hash the actual bytes and check
//!      that hash against the manifest — **exec-by-hash**. The filesystem has
//!      no authority to run code; only content does.
//!   3. Apply the laundering ban: an attested interpreter fed input the agent
//!      wrote is moved to the agent lane for that invocation.
//!   4. Refuse with a structured record rather than an error string, because
//!      the failure surface is how an agent corrects itself.
//!
//! Tool-lane code runs with its attested authority. Agent-lane code is entered
//! only through the Landlock and seccomp boundary immediately before execve;
//! it never inherits tool-lane authority.

use celln_manifest::{resolve_exec_lane, Hash, Input, Lane, Manifest};
use pilot::{exec, ExecOutcome};
use serde::Deserialize;
use std::ffi::CString;
use std::io;
use std::os::unix::process::CommandExt;

const WORKSPACE: &str = "/celln/work";

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    _reserved: i32,
}

// Linux UAPI values, kept here rather than inferred from the host libc: these
// instructions execute in the static x86_64 guest, where this ABI is fixed.
const LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const LANDLOCK_ADD_RULE: libc::c_long = 445;
const LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_long = 1;
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;

const FS_ALL: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER;

/// Enter a sealed image as the filesystem root, immediately before `execve`.
///
/// A single static binary can be exec'd straight off the sealed mount, but a
/// real tool is a *closure* — the binary plus its loader plus every shared
/// object it needs — and a dynamic loader resolves those by absolute path
/// (`/lib64/ld-linux-x86-64.so.2`). Mounted at `/tools`, none of those paths
/// exist. `chroot` makes the sealed image the root, so the closure resolves
/// against itself and never against the host.
///
/// This runs in the child, after fork and before exec, so pilot itself keeps
/// its own view of the filesystem — it still has to reach `/celln/manifest.json`
/// for the next request.
fn enter_root(root: &str) -> io::Result<()> {
    let path = CString::new(root).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    unsafe {
        if libc::chroot(path.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let slash = CString::new("/").expect("constant path");
        if libc::chdir(slash.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Apply the agent lane immediately before `execve`. The parent stays pilot and
/// retains its narrow supervisory authority; the child can read/execute tools,
/// write only its workspace, and cannot create a network socket.
///
/// `workspace` is the one writable path. Without a sealed image that is the
/// initramfs scratch dir; inside one it is the tmpfs the caller mounted over
/// the image's own `/tmp`, because the image itself is read-only by hardware
/// and nothing in it can be written to.
fn enter_agent_lane(workspace: &str, exec_path: &str) -> io::Result<()> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        let rules = LandlockRulesetAttr {
            handled_access_fs: FS_ALL,
        };
        let ruleset = libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &rules as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        ) as i32;
        if ruleset < 0 {
            return Err(io::Error::last_os_error());
        }
        let add = |path: &str, access: u64| -> io::Result<()> {
            let path = CString::new(path).expect("constant path");
            let fd = libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let rule = LandlockPathBeneathAttr {
                allowed_access: access,
                parent_fd: fd,
                _reserved: 0,
            };
            let rc = libc::syscall(
                LANDLOCK_ADD_RULE,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const LandlockPathBeneathAttr,
                0,
            );
            libc::close(fd);
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        // The executable being run is the only tool the agent lane receives.
        // Do not grant the `/tools` directory: that would let it discover and
        // read every future host-lent tool by name.
        //
        // Inside a chroot'ed sealed image this rule is already satisfied by
        // construction — the root *is* the one image being lent, so the grant
        // on "/" below is scoped to exactly that image and nothing else. A
        // second image is a second mount the child never sees.
        add(
            exec_path,
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
        )?;
        // pilot-fetch uses I/O ports to talk to the host broker, not sockets.
        // On the stock guest kernel, Landlock only authorises execve from this
        // initramfs when EXECUTE is granted on its root hierarchy; a rule for
        // the binary or its directory still returns EACCES. The kernel also
        // requires READ_FILE for this static execve. The image is immutable;
        // write access remains limited to the workspace, and egress remains
        // host-authorised by the broker.
        // READ_DIR as well as READ_FILE: a real tool resolves its own runtime
        // by walking directories (python locates `encodings` before it can
        // start), and without it the interpreter dies before running anything.
        // It grants no reach a READ_FILE on this hierarchy did not already —
        // inside a chroot the hierarchy is the one image being lent.
        add(
            "/",
            LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
        )?;
        add(workspace, FS_ALL)?;
        if libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::close(ruleset);
        let work =
            CString::new(workspace).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        if libc::chdir(work.as_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    install_network_seccomp()
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

fn install_network_seccomp() -> io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const EPERM: u32 = 1;
    let denied = [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_shutdown,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_ptrace,
        libc::SYS_bpf,
    ];
    let mut filter = Vec::with_capacity(2 + denied.len() * 2);
    filter.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });
    for syscall in denied {
        filter.push(SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | EPERM,
        });
    }
    filter.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    let program = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };
    unsafe {
        if libc::syscall(libc::SYS_seccomp, 1, 0, &program as *const SockFprog) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Report an observation the host can assert on, same protocol the guest init
/// uses: one `CELLN:key=value` line per fact, on the console.
fn report(key: &str, val: &str) {
    println!("CELLN:{key}={val}");
}

/// Where the host stages the cell's manifest and the tools it attested.
const MANIFEST: &str = "/celln/manifest.json";
const TOOLS_DIR: &str = "/celln/tools";

/// What the host asked this cell to run, if anything. Staged next to the
/// manifest rather than passed on the kernel cmdline: a request to run
/// something is data, and it goes through the same hash check as everything
/// else regardless of how it arrived.
const RUN_REQUEST: &str = "/celln/run.json";

#[derive(Deserialize)]
struct RunRequest {
    /// Where the bytes live in the cell — normally on the sealed DAX mount.
    ///
    /// When `root` is set this is relative to *that* root, not to pilot's own
    /// filesystem, because the child is chroot'ed before it execs.
    path: String,
    /// What the agent calls it. Only used for reporting; authority comes from
    /// the hash, never from the name or the path.
    alias: String,
    #[serde(default)]
    args: Vec<String>,
    /// Whether the input this invocation is being fed was written by the agent.
    #[serde(default)]
    agent_authored_input: bool,
    /// A sealed image mount to enter as `/` before exec, for tools that are a
    /// dependency closure rather than one static binary. Absent means the old
    /// behaviour: exec `path` directly out of the sealed mount.
    #[serde(default)]
    root: Option<String>,
}

/// One cell can be asked to run several tools. Each invocation is hash-checked
/// and lane-resolved on its own; sharing a cell grants nothing.
#[derive(Deserialize)]
struct RunFile {
    #[serde(default)]
    runs: Vec<RunRequest>,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    alias: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    agent_authored_input: bool,
}

impl RunFile {
    fn invocations(self) -> Vec<RunRequest> {
        if !self.runs.is_empty() {
            let root = self.root;
            return self
                .runs
                .into_iter()
                .map(|mut r| {
                    r.root = r.root.or_else(|| root.clone());
                    r
                })
                .collect();
        }
        match (self.path, self.alias) {
            (Some(path), Some(alias)) => vec![RunRequest {
                path,
                alias,
                args: self.args,
                agent_authored_input: self.agent_authored_input,
                root: self.root,
            }],
            _ => Vec::new(),
        }
    }
}

/// Mount a small writable tmpfs over `<root>/tmp`.
///
/// The sealed image is read-only *by hardware* — nothing in the guest can
/// write it, which is the whole point — but real tools assume somewhere to
/// scratch. This gives each cell its own private tmpfs at a path the image
/// already provides, so the read-only image stays shareable across every cell
/// while the writes stay per-cell.
fn mount_scratch(root: &str) -> io::Result<()> {
    let target = CString::new(format!("{root}/tmp"))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let fstype = CString::new("tmpfs").expect("constant");
    let source = CString::new("tmpfs").expect("constant");
    unsafe {
        if libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn main() {
    report("pilot", "alive");

    let manifest: Manifest = match std::fs::read(MANIFEST) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(m) => m,
            Err(e) => {
                report("pilot_manifest", "unparseable");
                eprintln!("pilot: {MANIFEST}: {e}");
                return finish(1);
            }
        },
        Err(_) => {
            report("pilot_manifest", "absent");
            return finish(1);
        }
    };

    // A manifest that does not verify is not a manifest. Say so loudly: this
    // is the difference between attested execution and a list of hashes.
    let signed = manifest.verify_standin();
    report("pilot_manifest", if signed { "signed" } else { "UNSIGNED" });
    report("pilot_entries", &manifest.len().to_string());

    // Everything the host staged, hashed here rather than trusted. A tool that
    // was tampered with between attestation and now hashes differently and is
    // refused, which is the entire point of exec-by-hash.
    let mut checked = 0usize;
    let mut permitted = 0usize;
    if let Ok(dir) = std::fs::read_dir(TOOLS_DIR) {
        let mut entries: Vec<_> = dir.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            checked += 1;
            let hash = Hash::of(&bytes);
            let name = path.file_name().unwrap_or_default().to_string_lossy();

            // The agent wrote whatever this is being fed, so an interpreter
            // must be demoted. That is the laundering ban, applied in-cell.
            match exec(&manifest, &hash, Input::File(Lane::Data)) {
                ExecOutcome::Run { lane, .. } => {
                    permitted += 1;
                    report(&format!("pilot_exec_{name}"), &format!("permitted:{lane}"));
                    // Say why, since "tool" vs "data" is the whole decision.
                    if let Some(entry) = manifest.get(&hash) {
                        let undemoted = resolve_exec_lane(entry, Input::None);
                        if undemoted != lane {
                            report(
                                &format!("pilot_demoted_{name}"),
                                "interpreter fed agent-authored input",
                            );
                        }
                    }
                }
                ExecOutcome::Denied(e) => {
                    report(&format!("pilot_exec_{name}"), "denied");
                    // The structured record, on the console, for the agent.
                    for line in e.to_json().lines() {
                        println!("CELLN:explain {line}");
                    }
                }
            }
        }
    }
    report("pilot_checked", &checked.to_string());
    report("pilot_permitted", &permitted.to_string());

    // An unattested hash must be refused even though nothing else about it is
    // suspicious. Proving that in-cell, every boot, is cheap.
    let ghost = Hash::of(b"code the agent wrote itself");
    match exec(&manifest, &ghost, Input::None) {
        ExecOutcome::Denied(_) => report("pilot_unattested", "refused"),
        ExecOutcome::Run { .. } => report("pilot_unattested", "PERMITTED"),
    }

    run_requested(&manifest);

    report("pilot", "done");
    finish(0)
}

/// Run what the host asked for, if it asked for anything.
///
/// The path is where to find the bytes; it carries no authority. Authority
/// comes from hashing what is actually at that path and finding that hash in
/// the manifest. A tool swapped after attestation hashes differently and never
/// runs, which is the only reason a filesystem is safe to exec out of at all.
fn run_requested(manifest: &Manifest) {
    let Ok(bytes) = std::fs::read(RUN_REQUEST) else {
        return; // nothing asked of this cell
    };
    let file: RunFile = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(e) => {
            report("pilot_run", "unparseable");
            eprintln!("pilot: {RUN_REQUEST}: {e}");
            return;
        }
    };

    // Each sealed root needs its scratch mounted once, not once per tool.
    let mut mounted: Vec<String> = Vec::new();
    let invocations = file.invocations();
    report("pilot_runs", &invocations.len().to_string());
    for req in invocations {
        if let Some(root) = req.root.clone() {
            if !mounted.contains(&root) {
                match mount_scratch(&root) {
                    Ok(()) => report("pilot_scratch", "tmpfs"),
                    Err(e) => {
                        report("pilot_scratch", "failed");
                        eprintln!("pilot: tmpfs on {root}/tmp: {e}");
                    }
                }
                mounted.push(root);
            }
        }
        run_one(manifest, &req);
    }
}

fn run_one(manifest: &Manifest, req: &RunRequest) {
    // Where pilot itself can read the bytes, which is not where the child will
    // exec them from: the child is chroot'ed, so its `/usr/bin/x` is pilot's
    // `/tools/usr/bin/x`. Hash the bytes here, before any chroot, so the
    // exec-by-hash check is made against the file that will actually run.
    let host_view = match &req.root {
        Some(root) => format!("{root}{}", req.path),
        None => req.path.clone(),
    };
    let Ok(code) = std::fs::read(&host_view) else {
        report(&format!("pilot_run_{}", req.alias), "absent");
        return;
    };
    let hash = Hash::of(&code);

    // Anything the agent wrote demotes this invocation, per the laundering ban.
    let input = if req.agent_authored_input {
        Input::File(Lane::Data)
    } else {
        Input::None
    };

    match exec(manifest, &hash, input) {
        ExecOutcome::Denied(e) => {
            report(&format!("pilot_run_{}", req.alias), "denied");
            for line in e.to_json().lines() {
                println!("CELLN:explain {line}");
            }
        }
        ExecOutcome::Run { lane, .. } => {
            report(
                &format!("pilot_run_{}", req.alias),
                &format!("permitted:{lane}"),
            );

            // Everything between these markers is the program's own output.
            // The host slices on them so a cell can be piped like any process.
            println!("CELLN:out-begin");
            let mut command = std::process::Command::new(&req.path);
            command.args(&req.args);
            let root = req.root.clone();
            let exec_path = req.path.clone();
            // Inside a sealed image the only writable place is the tmpfs just
            // mounted; outside one it is the initramfs scratch dir.
            let workspace = if root.is_some() { "/tmp" } else { WORKSPACE }.to_string();
            let confine = lane != Lane::Tool;
            if root.is_some() || confine {
                unsafe {
                    command.pre_exec(move || {
                        // Order matters: chroot first, so every Landlock rule
                        // below is resolved inside the image rather than
                        // against pilot's own filesystem.
                        if let Some(r) = &root {
                            enter_root(r)?;
                        }
                        if confine {
                            enter_agent_lane(&workspace, &exec_path)?;
                        }
                        Ok(())
                    });
                }
            }
            let status = command.status();
            println!("CELLN:out-end");

            match status {
                Ok(s) => report(
                    &format!("pilot_run_{}_exit", req.alias),
                    &s.code().unwrap_or(-1).to_string(),
                ),
                Err(e) => {
                    report(&format!("pilot_run_{}", req.alias), "exec-failed");
                    eprintln!("pilot: exec {}: {e}", req.path);
                }
            }
        }
    }
}

/// Pilot is PID 1 in a cell, so returning is not an option — the kernel panics
/// if init exits. Ask for a reboot, which the host sees as a clean shutdown.
///
/// Only when we are actually PID 1. Running this binary on a developer's own
/// machine as root would otherwise reboot their machine, which is not a
/// mistake anyone should be able to make twice.
fn finish(code: i32) {
    println!("CELLN:done");
    if std::process::id() == 1 {
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_AUTOBOOT);
        }
    }
    std::process::exit(code);
}
