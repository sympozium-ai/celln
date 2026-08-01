//! Booting a **stock Linux kernel** in a Nouscell microVM.
//!
//! M1/M2 proved the enforcement layer with hand-assembled, kernel-less guests.
//! That was the right way to prove sealing (a kernel-less guest can be made
//! strictly more hostile than a stock kernel), but it leaves one claim
//! unreachable: that a *real* guest can execute out of sealed pages. The blocker
//! named in `docs/findings/m2.md` is the **VFS↔memslot join** — a guest
//! `mmap(PROT_EXEC)` of `/tools/python` must land on the sealed memslot rather
//! than on a page-cache copy of it.
//!
//! This module is the vehicle for that work: it boots an unmodified distro
//! bzImage via the 64-bit Linux boot protocol, with a serial console so the
//! boot is observable, and it seals tool regions into the running guest the
//! same way [`super::kvm::KvmVmm`] does.
//!
//! **What is now proven** (`guest_userspace_mapping_of_a_sealed_tool_is_the_real_thing`,
//! and `make boot-kvm`): a real guest *userspace process* under a stock kernel
//! maps the sealed region, verifies by magic that it is the sealed page-set
//! rather than a copy, **executes code out of it**, and cannot modify it — its
//! write is refused below the guest and the host counts the refusal. So the
//! seal governs a userspace mapping, and sealed pages are genuinely r-x to a
//! real process.
//!
//! **And in its production shape** (`guest_opens_a_tool_by_path_and_gets_the_sealed_pages`):
//! the sealed region is declared as persistent memory, the nvdimm drivers turn
//! it into `/dev/pmem0`, an ext2 image inside it is mounted `dax=always`, and
//! the guest does `open("/tools/probe")` + `mmap(PROT_EXEC)`. It gets the sealed
//! pages — executes from them, and its write is refused. DAX is what makes the
//! mapping direct; the refused write is what proves it, because a page-cache
//! copy would have absorbed it silently.
//!
//! The `/dev/mem` probe is kept alongside it: it is the shortest unambiguously
//! direct mapping, so it isolates "does the seal survive a userspace mapping"
//! from "does this filesystem mechanism copy". When the DAX path regresses,
//! having both says which half broke.
//!
//! Deliberately kept separate from `KvmVmm`: that type is built around the
//! 16 KiB CoW proof guest and its properties are load-bearing for M1/M2. This
//! is a second, larger vehicle; unifying them belongs with the mote kernel,
//! once we know what a mote actually looks like.

use super::kvm::{shared_tool_bytes, shared_tool_map, shared_tool_map_existing, PAGE};
use super::VmmError;
use kvm_bindings::{kvm_userspace_memory_region, KVM_MAX_CPUID_ENTRIES, KVM_MEM_READONLY};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd, VmFd};
use nous_manifest::Hash;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

// ---- guest physical layout (the conventional one; Firecracker uses the same) ----

/// Boot GDT.
pub const GDT_GPA: u64 = 0x500;
/// `boot_params` — the "zero page" handed to the kernel in %rsi.
pub const ZERO_PAGE_GPA: u64 = 0x7000;
/// Transitional page tables: PML4, PDPT, PD (identity-map the first 1 GiB).
pub const PML4_GPA: u64 = 0x9000;
pub const PDPT_GPA: u64 = 0xa000;
pub const PD_GPA: u64 = 0xb000;
/// Kernel command line.
pub const CMDLINE_GPA: u64 = 0x20000;
/// Where the protected-mode kernel image is loaded.
pub const KERNEL_GPA: u64 = 0x10_0000;
/// Top of the low usable memory band (EBDA below it).
pub const EBDA_GPA: u64 = 0x9_fc00;
/// Sealed tool regions live in a **hole punched inside the RAM span**, not
/// above it. Guest RAM is mapped as two memslots either side of this window,
/// and the window itself is backed by read-only sealed memslots.
///
/// The obvious layout — park tools above the top of RAM — does not work, and
/// fails in a way that wastes a lot of time: the kernel accepts the e820 entry
/// and prints it (`persistent RAM (type 12)`), but `last_pfn` stops at the top
/// of real RAM, so the region is never registered in `/proc/iomem`,
/// `register_e820_pmem()` finds nothing, and no pmem device appears. Every
/// module loads successfully and the device simply is not there.
///
/// `guest/init/init.c` hardcodes this address (`TOOL_GPA`). The coupling is
/// deliberate and self-checking: the guest verifies [`PROBE_MAGIC`] before
/// trusting anything it reads there, so drift shows up as a loud mismatch
/// rather than a silent pass.
pub const TOOL_WINDOW_GPA: u64 = 0x600_0000; // 96 MiB
/// Size of that hole. RAM resumes above it.
pub const TOOL_WINDOW_SIZE: u64 = 32 << 20;

/// Marker at the start of the probe tool, so the guest can tell "I mapped the
/// sealed page-set" apart from "I mapped something plausible".
pub const PROBE_MAGIC: &[u8; 8] = b"NOUSTOOL";
/// Offset of the callable function within the probe tool.
pub const PROBE_FN_OFF: usize = 16;
/// What that function returns.
pub const PROBE_FN_RETURNS: u8 = 0x5a;

/// The probe "tool": a magic marker plus a real x86-64 function
/// (`mov eax, 0x5a; ret`) for the guest to call. Executing this from a guest
/// userspace mapping is what proves the sealed pages are genuinely r-x to a
/// real process, not merely present.
pub fn probe_tool() -> Vec<u8> {
    let mut t = vec![0u8; PAGE];
    t[..8].copy_from_slice(PROBE_MAGIC);
    t[PROBE_FN_OFF..PROBE_FN_OFF + 6].copy_from_slice(&[
        0xb8,
        PROBE_FN_RETURNS,
        0x00,
        0x00,
        0x00, // mov eax, 0x5a
        0xc3, // ret
    ]);
    t
}

const RAM_SLOT_LOW: u32 = 0;
const RAM_SLOT_HIGH: u32 = 1;
const FIRST_TOOL_SLOT: u32 = 2;

/// e820 type 12: persistent memory declared the legacy (non-ACPI) way. This is
/// what makes the nvdimm drivers claim the region and expose it as `/dev/pmem0`,
/// which is what a DAX filesystem can then be mounted from.
const E820_PRAM: u32 = 12;

/// PCI type-1 configuration address port.
const PCI_CONFIG_ADDR: u16 = 0xcf8;

/// Unused port the guest writes to signal "this cell is doing userspace work".
/// One exit, timestamped by the host — the cheapest observable a guest can
/// produce. Saying it on the console instead measures our 8250 emulation, not
/// spawn latency. Must match NOUS_LIVE_PORT in guest/init/init.c.
const LIVE_SIGNAL_PORT: u16 = 0x3f0;

// ---- setup_header / boot_params offsets (Documentation/x86/boot.rst) ----

const HDR_START: usize = 0x1f1;
const HDR_END: usize = 0x270; // setup_header is 127 bytes
const HDR_SETUP_SECTS: usize = 0x1f1;
const HDR_BOOT_FLAG: usize = 0x1fe;
const HDR_MAGIC: usize = 0x202;
const HDR_VERSION: usize = 0x206;
const HDR_TYPE_OF_LOADER: usize = 0x210;
const HDR_LOADFLAGS: usize = 0x211;
const HDR_RAMDISK_IMAGE: usize = 0x218;
const HDR_RAMDISK_SIZE: usize = 0x21c;
const HDR_CMD_LINE_PTR: usize = 0x228;
const HDR_INIT_SIZE: usize = 0x260;
const BP_E820_ENTRIES: usize = 0x1e8;
const BP_E820_TABLE: usize = 0x2d0;

const E820_RAM: u32 = 1;
const LOADED_HIGH: u8 = 0x01;

// ---- long mode control-register bits ----

const CR0_PE: u64 = 1 << 0;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

const PDE_PRESENT: u64 = 1 << 0;
const PDE_RW: u64 = 1 << 1;
const PDE_PS: u64 = 1 << 7;

/// Selectors mandated by the 64-bit boot protocol.
const SEL_CODE: u16 = 0x10;
const SEL_DATA: u16 = 0x18;

fn errno(what: &str) -> VmmError {
    VmmError::Backend(format!("{what}: {}", std::io::Error::last_os_error()))
}

fn kvm_err(what: &str, e: kvm_ioctls::Error) -> VmmError {
    VmmError::Backend(format!("{what}: {e}"))
}

/// How a boot run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEnd {
    /// The guest asked to reboot or shut down — with `panic=-1` and no init,
    /// this is the normal end of a successful boot.
    Shutdown,
    /// The watchdog stopped the run.
    TimedOut,
    /// The vCPU halted with nothing left to wake it.
    Halted,
    /// The guest printed the marker set by
    /// [`LinuxCell::stop_when_guest_prints`]. The vCPU is at a clean exit
    /// boundary and can be parked with [`LinuxCell::park`].
    Parked,
}

/// What a boot run produced.
#[derive(Debug)]
pub struct BootReport {
    /// Everything the guest wrote to the serial console.
    pub console: String,
    pub end: BootEnd,
    pub exits: u64,
    pub elapsed: Duration,
    /// Guest writes into a sealed tool region that the hardware refused. The
    /// host-side counterpart to the guest's own account of the same event.
    pub sealed_writes_blocked: u64,
    /// When the guest first signalled that it was doing userspace work. The
    /// spawn-latency clock stops here.
    pub live_signal_at: Option<Instant>,
    /// True when a tool was revoked mid-run by [`LinuxCell::revoke_when_guest_prints`].
    pub revoked_live: bool,
}

impl BootReport {
    /// Did the kernel get far enough to identify itself?
    pub fn reached_kernel(&self) -> bool {
        self.console.contains("Linux version")
    }

    /// Did it get all the way to userspace hand-off (init, or the panic that
    /// replaces it when there is no initramfs)?
    pub fn reached_userspace_handoff(&self) -> bool {
        self.console.contains("Run /init")
            || self.console.contains("Kernel panic")
            || self.console.contains("Freeing unused kernel image")
    }

    /// Did a cell forked from a parked mote reach userspace and do work?
    /// This is what "spawn is a fork, not a boot" has to mean concretely.
    pub fn cell_went_live(&self) -> bool {
        self.console.contains("NOUS:cell=live")
    }

    /// Did our guest init actually run? Distinct from a hand-off that panics.
    pub fn guest_init_ran(&self) -> bool {
        self.console.contains("NOUS:init=alive")
    }

    /// The value guest init reported for `key`, if it reported one. This is how
    /// guest-side claims reach the host: the guest states what it observed, the
    /// host asserts on it.
    pub fn guest_report(&self, key: &str) -> Option<&str> {
        let needle = format!("NOUS:{key}=");
        self.console
            .lines()
            .find_map(|l| l.split_once(&needle).map(|(_, v)| v.trim()))
    }

    /// First `n` console lines — handy for test output.
    pub fn head(&self, n: usize) -> String {
        self.console.lines().take(n).collect::<Vec<_>>().join("\n")
    }

    /// Last `n` console lines.
    pub fn tail(&self, n: usize) -> String {
        let lines: Vec<&str> = self.console.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }
}

/// A parsed bzImage.
struct BzImage {
    bytes: Vec<u8>,
    /// Offset of the protected-mode kernel within `bytes`.
    pm_offset: usize,
}

impl BzImage {
    fn load(path: &Path) -> Result<Self, VmmError> {
        let bytes = std::fs::read(path)
            .map_err(|e| VmmError::Backend(format!("reading {}: {e}", path.display())))?;
        if bytes.len() < HDR_END {
            return Err(VmmError::Backend("kernel image too small".into()));
        }
        if &bytes[HDR_MAGIC..HDR_MAGIC + 4] != b"HdrS" {
            return Err(VmmError::Backend(format!(
                "{} is not a bzImage (no HdrS magic)",
                path.display()
            )));
        }
        if u16::from_le_bytes([bytes[HDR_BOOT_FLAG], bytes[HDR_BOOT_FLAG + 1]]) != 0xaa55 {
            return Err(VmmError::Backend("bad boot flag".into()));
        }
        let version = u16::from_le_bytes([bytes[HDR_VERSION], bytes[HDR_VERSION + 1]]);
        if version < 0x0206 {
            return Err(VmmError::Unsupported(format!(
                "boot protocol {:x}.{:02x} is older than 2.06",
                version >> 8,
                version & 0xff
            )));
        }
        let setup_sects = match bytes[HDR_SETUP_SECTS] {
            0 => 4, // 0 means 4, per the protocol
            n => n as usize,
        };
        let pm_offset = (setup_sects + 1) * 512;
        if pm_offset >= bytes.len() {
            return Err(VmmError::Backend("setup_sects past end of image".into()));
        }
        Ok(BzImage { bytes, pm_offset })
    }

    fn protected_mode_kernel(&self) -> &[u8] {
        &self.bytes[self.pm_offset..]
    }

    fn init_size(&self) -> u32 {
        u32::from_le_bytes(
            self.bytes[HDR_INIT_SIZE..HDR_INIT_SIZE + 4]
                .try_into()
                .expect("4 bytes"),
        )
    }
}

/// How to boot.
#[derive(Debug, Clone)]
pub struct BootConfig {
    pub kernel: PathBuf,
    pub initrd: Option<PathBuf>,
    pub cmdline: String,
    pub mem_size: usize,
    /// Wall-clock budget for the run.
    pub timeout: Duration,
    /// Declare the sealed tool window to the kernel as persistent memory, so
    /// the nvdimm drivers turn it into `/dev/pmem0` and a filesystem inside it
    /// can be mounted with DAX. Size in bytes; see [`BootConfig::with_pmem`].
    pub pmem_bytes: Option<usize>,
}

impl BootConfig {
    /// A boot that exercises the kernel and then exits: serial console on,
    /// panic reboots immediately (which, with no initramfs, is how a healthy
    /// boot ends), and the devices we do not emulate are switched off.
    ///
    /// `pci=conf1` is load-bearing and easy to mistake for noise. We emulate no
    /// PCI devices, so switching PCI off looks like an obvious cleanup — but
    /// persistent-memory e820 resources are inserted by
    /// `e820__reserve_resources_late()`, whose only caller on x86 is
    /// `pcibios_resource_survey()`. No PCI initialisation means no pmem
    /// resource, means no `/dev/pmem0`, means no DAX — while every module still
    /// loads successfully and reports nothing wrong.
    pub fn new(kernel: impl Into<PathBuf>) -> Self {
        BootConfig {
            kernel: kernel.into(),
            initrd: None,
            cmdline: "console=ttyS0 earlyprintk=serial,ttyS0,115200 \
                      panic=-1 reboot=t nokaslr tsc=reliable pci=conf1 \
                      i8042.noaux i8042.nomux i8042.nopnp i8042.dumbkbd"
                .into(),
            mem_size: 256 << 20,
            timeout: Duration::from_secs(20),
            pmem_bytes: None,
        }
    }

    /// Declare `len` bytes at [`TOOL_WINDOW_GPA`] as persistent memory
    /// (`memmap=<len>!<gpa>`). This is what lets a sealed filesystem image be
    /// reached by *file path* under DAX rather than through `/dev/mem`.
    ///
    /// The region is outside the e820 RAM map, so this is the only thing that
    /// tells the kernel it exists at all — and it announces it as pmem, which
    /// is memory the kernel maps but never allocates from.
    pub fn with_pmem(mut self, len: usize) -> Self {
        self.pmem_bytes = Some(len);
        self
    }

    /// Boot with the guest initramfs (`scripts/mkinitramfs.sh`), so the run
    /// reaches real userspace instead of panicking for want of a root fs.
    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    /// The initramfs built by `make initramfs`, if it is there.
    pub fn built_initramfs() -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|root| root.join("target/nous-initramfs.cpio"))?;
        p.exists().then_some(p)
    }

    /// Pick a kernel from `/boot` to boot.
    ///
    /// Prefers the newest kernel that *also* has its modules installed under
    /// `/lib/modules`, because the DAX probe loads nvdimm modules and module
    /// vermagic is checked exactly — booting 7.1.4 with 7.1.3's modules fails
    /// in a way that looks like a DAX problem and isn't. Falls back to the
    /// newest readable image when nothing has matching modules.
    ///
    /// `scripts/mkinitramfs.sh` implements the same rule; keep them in step.
    pub fn host_kernel() -> Option<PathBuf> {
        let mut found: Vec<PathBuf> = std::fs::read_dir("/boot")
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("vmlinuz-") && !n.contains("rescue"))
            })
            .filter(|p| std::fs::File::open(p).is_ok())
            .collect();
        found.sort();
        let with_modules = found
            .iter()
            .rev()
            .find(|p| Self::modules_dir_for(p).is_some())
            .cloned();
        with_modules.or_else(|| found.last().cloned())
    }

    /// `/lib/modules/<version>` for a `/boot/vmlinuz-<version>` image.
    pub fn modules_dir_for(kernel: &Path) -> Option<PathBuf> {
        let ver = kernel.file_name()?.to_str()?.strip_prefix("vmlinuz-")?;
        let dir = PathBuf::from("/lib/modules").join(ver);
        dir.is_dir().then_some(dir)
    }
}

/// A minimal 8250 UART — enough for the kernel console to talk to us.
///
/// Both console paths must work, and they behave differently: `earlyprintk`
/// polls the line-status register, but the real `ttyS0` driver transmits
/// **interrupt-driven** — it sends one byte, then waits for a THR-empty
/// interrupt before sending the next. Without IRQ 4 wired, userspace output
/// stops dead after a single character.
#[derive(Default)]
struct Serial {
    out: Vec<u8>,
    lcr: u8,
    ier: u8,
    mcr: u8,
}

impl Serial {
    const BASE: u16 = 0x3f8;
    const IRQ: u32 = 4;
    const IER_THRI: u8 = 0x02;
    const IIR_NONE: u8 = 0x01;
    const IIR_THRE: u8 = 0x02;
    const LSR_THRE: u8 = 0x20;
    const LSR_TEMT: u8 = 0x40;

    fn dlab(&self) -> bool {
        self.lcr & 0x80 != 0
    }

    /// Returns true when the guest should be interrupted: we are an infinitely
    /// fast transmitter, so the holding register is empty the instant a byte
    /// is written, and again as soon as the driver enables the interrupt.
    fn write(&mut self, port: u16, val: u8) -> bool {
        match port - Self::BASE {
            0 if !self.dlab() => {
                self.out.push(val);
                self.ier & Self::IER_THRI != 0
            }
            1 if !self.dlab() => {
                self.ier = val;
                val & Self::IER_THRI != 0
            }
            3 => {
                self.lcr = val;
                false
            }
            4 => {
                self.mcr = val;
                false
            }
            _ => false,
        }
    }

    fn read(&self, port: u16) -> u8 {
        match port - Self::BASE {
            1 if !self.dlab() => self.ier,
            2 => {
                if self.ier & Self::IER_THRI != 0 {
                    Self::IIR_THRE
                } else {
                    Self::IIR_NONE
                }
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => Self::LSR_THRE | Self::LSR_TEMT, // always ready to transmit
            6 => 0xb0,                            // MSR: carrier detect, DSR, CTS
            _ => 0,
        }
    }
}

/// Ask for transparent huge pages when `NOUS_HUGEPAGE=1`.
///
/// A no-op unless the host allows shmem THP. Kept as advice rather than a hard
/// requirement so the same binary measures both ways: the point is the fault
/// count, and whether 2 MiB pages actually reduce it for a CoW-forked guest is
/// exactly the open question.
fn maybe_hugepage(ptr: *mut libc::c_void, len: usize) {
    if std::env::var_os("NOUS_HUGEPAGE").is_some() {
        unsafe { libc::madvise(ptr, len, libc::MADV_HUGEPAGE) };
    }
}

/// Host mmap backing guest memory.
///
/// Guest RAM is always backed by a memfd rather than anonymous memory, because
/// that is what makes a *booted* guest forkable: the template maps it
/// `MAP_SHARED` so its writes land in the memfd, and every cell forked from it
/// maps the same memfd `MAP_PRIVATE`. Clean pages are shared; a cell's writes
/// are private to it. Without the memfd there is no way to fork a live guest —
/// only to boot another one.
struct Mem {
    ptr: *mut u8,
    len: usize,
    /// The memfd this is a view of, when there is one.
    fd: Option<Arc<OwnedFd>>,
}

unsafe impl Send for Mem {}

impl Mem {
    /// A writable, shareable RAM image: the template a mote is parked in.
    ///
    /// Two huge-page paths, both off by default because both need host state
    /// this project will not change on its own (see `docs/findings/m1-spawn.md`):
    ///
    /// * `NOUS_HUGEPAGE=1` — `MADV_HUGEPAGE` on the mapping. Needs
    ///   `/sys/kernel/mm/transparent_hugepage/shmem_enabled` set to `advise` or
    ///   `always`; it is `never` on stock Fedora, where this is a silent no-op.
    /// * `NOUS_HUGETLB=1` — back the memfd with hugetlbfs outright. Needs
    ///   `vm.nr_hugepages` reserved, and **fails loudly** rather than falling
    ///   back, because a silent fallback would report a huge-page result for a
    ///   4 KiB run.
    fn memfd_shared(len: usize, name: &str) -> Result<Self, VmmError> {
        let cname =
            CString::new(name).map_err(|_| VmmError::Backend("memfd name contains NUL".into()))?;
        let hugetlb = std::env::var_os("NOUS_HUGETLB").is_some();
        let flags = if hugetlb {
            libc::MFD_CLOEXEC | libc::MFD_HUGETLB
        } else {
            libc::MFD_CLOEXEC
        };
        let raw = unsafe { libc::memfd_create(cname.as_ptr(), flags) };
        if raw < 0 {
            if hugetlb {
                return Err(VmmError::Backend(format!(
                    "memfd_create(MFD_HUGETLB): {}. Reserve huge pages first: \
                     sudo sysctl -w vm.nr_hugepages=<n>",
                    std::io::Error::last_os_error()
                )));
            }
            return Err(errno("memfd_create guest RAM"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
            return Err(errno("ftruncate guest RAM"));
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            if hugetlb {
                // memfd_create(MFD_HUGETLB) succeeds even with no huge pages
                // reserved; it is the mmap that fails, with a bare ENOMEM that
                // says nothing about why.
                return Err(VmmError::Backend(format!(
                    "mmap of hugetlb guest RAM: {}. {} huge pages are reserved; \
                     {len} bytes needs about {}. Try: sudo sysctl -w vm.nr_hugepages={}",
                    std::io::Error::last_os_error(),
                    std::fs::read_to_string("/proc/sys/vm/nr_hugepages")
                        .unwrap_or_default()
                        .trim(),
                    len.div_ceil(2 << 20),
                    len.div_ceil(2 << 20) * 2,
                )));
            }
            return Err(errno("mmap guest RAM (shared)"));
        }
        maybe_hugepage(ptr, len);
        Ok(Mem {
            ptr: ptr as *mut u8,
            len,
            fd: Some(Arc::new(fd)),
        })
    }

    /// A copy-on-write view of a parked mote. This is the fork.
    ///
    /// `NOUS_PREFAULT=1` populates the mapping up front instead of letting the
    /// resumed guest fault its working set in one page at a time. That is not
    /// obviously a win — it moves cost from activation to the fork call and
    /// touches every page — which is exactly why it is measurable rather than
    /// assumed. See `docs/findings/m1-spawn.md`.
    fn cow_of(fd: &Arc<OwnedFd>, len: usize) -> Result<Self, VmmError> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(errno("mmap guest RAM (CoW)"));
        }
        maybe_hugepage(ptr, len);
        if std::env::var_os("NOUS_PREFAULT").is_some() {
            // MADV_POPULATE_READ: fault in the shared pages now, read-only, so
            // sharing survives; a guest write still takes its own CoW fault.
            unsafe {
                libc::madvise(ptr, len, 22 /* MADV_POPULATE_READ */)
            };
        }
        Ok(Mem {
            ptr: ptr as *mut u8,
            len,
            fd: Some(fd.clone()),
        })
    }

    #[allow(dead_code)]
    fn anon(len: usize) -> Result<Self, VmmError> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(errno("mmap guest RAM"));
        }
        Ok(Mem {
            ptr: ptr as *mut u8,
            len,
            fd: None,
        })
    }

    fn write(&self, gpa: u64, bytes: &[u8]) -> Result<(), VmmError> {
        let off = gpa as usize;
        if off.checked_add(bytes.len()).map_or(true, |e| e > self.len) {
            return Err(VmmError::Backend(format!(
                "write of {} bytes at {gpa:#x} outside {} byte RAM",
                bytes.len(),
                self.len
            )));
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(off), bytes.len()) };
        Ok(())
    }
}

impl Drop for Mem {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

/// MSRs that have to travel with a snapshot for a booted Linux guest to resume.
///
/// Not the full `KVM_GET_MSR_INDEX_LIST` — most of that is not restorable and
/// the failures are per-MSR and silent. This is the set a resumed guest
/// actually needs: syscall entry, segment bases, TSC, and the KVM paravirt
/// clock, which the guest is using (`kvm-clock: using msrs 4b564d01/4b564d00`
/// in the boot log) and without which time stops making sense after a fork.
const SNAPSHOT_MSRS: &[u32] = &[
    0x0000_0174, // IA32_SYSENTER_CS
    0x0000_0175, // IA32_SYSENTER_ESP
    0x0000_0176, // IA32_SYSENTER_EIP
    0x0000_0010, // IA32_TSC
    0x0000_01a0, // IA32_MISC_ENABLE
    0xc000_0080, // EFER
    0xc000_0081, // STAR
    0xc000_0082, // LSTAR
    0xc000_0083, // CSTAR
    0xc000_0084, // SYSCALL_MASK
    0xc000_0100, // FS_BASE
    0xc000_0101, // GS_BASE
    0xc000_0102, // KERNEL_GS_BASE
    0x4b56_4d00, // KVM_WALL_CLOCK_NEW
    0x4b56_4d01, // KVM_SYSTEM_TIME_NEW
    0x4b56_4d02, // KVM_ASYNC_PF_EN
    0x4b56_4d03, // KVM_STEAL_TIME
    0x4b56_4d04, // KVM_PV_EOI_EN
];

/// Where the time goes when sealing a cell. Spawn latency turned out to be
/// dominated by fixed per-VM setup rather than by mote size -- halving the mote
/// barely moved it -- so the split is what says whether it can be optimised.
/// A **parked mote**: a Linux guest that has already booted, captured at a
/// known instruction, ready to be forked into cells.
///
/// This is the thing the whole design turns on. "The guest never boots in the
/// hot path" is only true if a booted guest can be forked, and forking a booted
/// guest means capturing everything that is not in RAM: vCPU registers, model
/// specific registers, the local APIC, the in-kernel interrupt controllers and
/// timer. RAM itself is not copied — it stays in the memfd and every cell maps
/// it copy-on-write.
#[derive(Debug, Clone, Copy, Default)]
pub struct ForkTiming {
    pub create_vm: Duration,
    pub cow_mmap: Duration,
    pub memslots: Duration,
    pub create_vcpu: Duration,
    pub restore_state: Duration,
}

pub struct Mote {
    ram: Arc<OwnedFd>,
    ram_size: usize,
    cpuid: kvm_bindings::CpuId,
    regs: kvm_bindings::kvm_regs,
    sregs: kvm_bindings::kvm_sregs,
    fpu: kvm_bindings::kvm_fpu,
    xcrs: kvm_bindings::kvm_xcrs,
    lapic: kvm_bindings::kvm_lapic_state,
    events: kvm_bindings::kvm_vcpu_events,
    mp_state: kvm_bindings::kvm_mp_state,
    msrs: Vec<(u32, u64)>,
    pic_master: kvm_bindings::kvm_irqchip,
    pic_slave: kvm_bindings::kvm_irqchip,
    ioapic: kvm_bindings::kvm_irqchip,
    pit: kvm_bindings::kvm_pit_state2,
    clock: kvm_bindings::kvm_clock_data,
    /// Serial register state, so a resumed guest's driver sees what it left.
    serial_lcr: u8,
    serial_ier: u8,
    serial_mcr: u8,
    /// Tools that were sealed into the template, re-sealed into every fork.
    tools: Vec<(Hash, u64, usize)>,
    cfg: BootConfig,
}

impl Mote {
    /// Size of the parked RAM image. Forks share these pages until they write.
    pub fn ram_size(&self) -> usize {
        self.ram_size
    }
}

/// SIGUSR1 with no SA_RESTART, so it interrupts a blocked `KVM_RUN`.
extern "C" fn wake(_sig: libc::c_int) {}

fn install_wake_handler() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = wake as *const () as usize;
        sa.sa_flags = 0; // crucially NOT SA_RESTART
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
    });
}

/// A microVM running a stock Linux kernel.
pub struct LinuxCell {
    _kvm: Kvm,
    vm: VmFd,
    vcpu: VcpuFd,
    /// Guest RAM. Held for the VM's lifetime: KVM keeps the mapping, and
    /// dropping it would unmap memory the guest is running out of.
    _mem: Mem,
    serial: Serial,
    /// The PCI configuration address latch (port 0xcf8).
    ///
    /// We emulate no PCI devices, but the kernel must still *detect* a type-1
    /// PCI config mechanism, and it detects it by writing this port and reading
    /// it back. Without that, `pci_legacy_init()` concludes the system has no
    /// PCI and returns before `pcibios_resource_survey()` — which is the only
    /// caller of `e820__reserve_resources_late()`, which is what finally
    /// inserts persistent-memory resources into iomem. No PCI, no pmem device.
    pci_cf8: u32,
    /// Revoke this tool the moment the guest prints this marker. See
    /// [`LinuxCell::revoke_when_guest_prints`].
    revoke_trigger: Option<(Hash, Vec<u8>)>,
    /// Stop the run when the guest prints this, leaving the vCPU at a clean
    /// boundary for [`LinuxCell::park`].
    stop_marker: Option<Vec<u8>>,
    /// Stop as soon as the guest writes [`LIVE_SIGNAL_PORT`].
    stop_on_signal: bool,
    /// The CPUID the vCPU was configured with; travels with a snapshot.
    cpuid: kvm_bindings::CpuId,
    tools: HashMap<Hash, (u32, u64, usize)>, // slot, gpa, len
    next_slot: u32,
    next_tool_gpa: u64,
    cfg: BootConfig,
}

impl LinuxCell {
    /// Build the VM, load the kernel, and place the vCPU at the 64-bit entry
    /// point with the boot protocol's required state. Does not run it.
    pub fn boot(cfg: BootConfig) -> Result<Self, VmmError> {
        let image = BzImage::load(&cfg.kernel)?;
        let needed = KERNEL_GPA as usize + image.init_size() as usize;
        if cfg.mem_size < needed {
            return Err(VmmError::Backend(format!(
                "mem_size {} too small; kernel needs {} (init_size {:#x})",
                cfg.mem_size,
                needed,
                image.init_size()
            )));
        }
        let tool_end = (TOOL_WINDOW_GPA + TOOL_WINDOW_SIZE) as usize;
        if cfg.mem_size <= tool_end {
            return Err(VmmError::Backend(format!(
                "mem_size {} must exceed the tool window end {tool_end:#x}; RAM \
                 has to continue above the hole for the kernel to register it",
                cfg.mem_size
            )));
        }
        if (needed as u64) > TOOL_WINDOW_GPA {
            return Err(VmmError::Backend(format!(
                "kernel needs {needed:#x}, which runs into the tool window at \
                 {TOOL_WINDOW_GPA:#x}"
            )));
        }
        if let Some(len) = cfg.pmem_bytes {
            if len as u64 > TOOL_WINDOW_SIZE {
                return Err(VmmError::Backend(format!(
                    "pmem image of {len} bytes exceeds the tool window \
                     ({TOOL_WINDOW_SIZE} bytes)"
                )));
            }
        }

        let kvm = Kvm::new().map_err(|e| VmmError::Unsupported(format!("/dev/kvm: {e}")))?;
        let vm = kvm.create_vm().map_err(|e| kvm_err("create_vm", e))?;
        vm.set_identity_map_address(0xfffb_c000)
            .map_err(|e| kvm_err("set_identity_map_address", e))?;
        vm.set_tss_address(0xfffb_d000)
            .map_err(|e| kvm_err("set_tss_address", e))?;
        // In-kernel PIC/IOAPIC/LAPIC and PIT: the kernel needs a timer to
        // calibrate against, and in-kernel HLT handling keeps idle cheap.
        vm.create_irq_chip()
            .map_err(|e| kvm_err("create_irq_chip", e))?;
        vm.create_pit2(Default::default())
            .map_err(|e| kvm_err("create_pit2", e))?;

        let mem = Mem::memfd_shared(cfg.mem_size, "nous-mote-ram")?;
        // RAM in two memslots, with the sealed tool window as a hole between
        // them. The host allocation stays contiguous, so a GPA is still an
        // offset into it; the hole is simply never mapped as RAM.
        let tool_end = TOOL_WINDOW_GPA + TOOL_WINDOW_SIZE;
        for (slot, gpa, len) in [
            (RAM_SLOT_LOW, 0u64, TOOL_WINDOW_GPA),
            (RAM_SLOT_HIGH, tool_end, cfg.mem_size as u64 - tool_end),
        ] {
            let region = kvm_userspace_memory_region {
                slot,
                flags: 0,
                guest_phys_addr: gpa,
                memory_size: len,
                userspace_addr: mem.ptr as u64 + gpa,
            };
            unsafe { vm.set_user_memory_region(region) }
                .map_err(|e| kvm_err("set_user_memory_region(RAM)", e))?;
        }

        // ---- lay out guest memory ----
        mem.write(KERNEL_GPA, image.protected_mode_kernel())?;

        let initrd = match &cfg.initrd {
            Some(p) => {
                let bytes = std::fs::read(p)
                    .map_err(|e| VmmError::Backend(format!("reading {}: {e}", p.display())))?;
                // Park it high, below the 4 GiB line and page-aligned.
                let addr = ((cfg.mem_size - bytes.len()) & !(PAGE - 1)) as u64;
                mem.write(addr, &bytes)?;
                Some((addr as u32, bytes.len() as u32))
            }
            None => None,
        };

        let mut cmdline = cfg.cmdline.clone().into_bytes();
        cmdline.push(0);
        mem.write(CMDLINE_GPA, &cmdline)?;
        mem.write(
            ZERO_PAGE_GPA,
            &zero_page(&image, cfg.mem_size, initrd, cfg.pmem_bytes),
        )?;
        mem.write(GDT_GPA, &boot_gdt())?;
        write_page_tables(&mem)?;

        // ---- vCPU ----
        let vcpu = vm.create_vcpu(0).map_err(|e| kvm_err("create_vcpu", e))?;
        let cpuid = kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(|e| kvm_err("get_supported_cpuid", e))?;
        vcpu.set_cpuid2(&cpuid)
            .map_err(|e| kvm_err("set_cpuid2", e))?;
        set_long_mode(&vcpu)?;

        let mut regs = vcpu.get_regs().map_err(|e| kvm_err("get_regs", e))?;
        regs.rflags = 0x0000_0002; // reserved bit; interrupts off
        regs.rip = KERNEL_GPA + 0x200; // startup_64
        regs.rsi = ZERO_PAGE_GPA; // boot_params, per the protocol
        regs.rsp = 0;
        regs.rbp = 0;
        vcpu.set_regs(&regs).map_err(|e| kvm_err("set_regs", e))?;

        Ok(LinuxCell {
            _kvm: kvm,
            vm,
            vcpu,
            _mem: mem,
            serial: Serial::default(),
            pci_cf8: 0,
            revoke_trigger: None,
            stop_marker: None,
            stop_on_signal: false,
            cpuid,
            tools: HashMap::new(),
            next_slot: FIRST_TOOL_SLOT,
            next_tool_gpa: TOOL_WINDOW_GPA,
            cfg,
        })
    }

    /// Seal an attested tool page-set into this guest, above RAM, exactly as
    /// [`super::kvm::KvmVmm`] does: a read-only memslot backed by the one
    /// shared host allocation for that hash. Returns the GPA it landed at.
    ///
    /// Nothing in the guest can *reach* this yet — that is the VFS↔memslot
    /// join, and it needs a guest-side consumer. The point of doing it here is
    /// that the sealed region is present and addressable in a real kernel's
    /// physical address space, which is the thing the join has to hook up.
    pub fn seal_tool(&mut self, hash: &Hash, bytes: &[u8]) -> Result<u64, VmmError> {
        if let Some(&(_, gpa, _)) = self.tools.get(hash) {
            return Ok(gpa);
        }
        let map = shared_tool_map(hash, bytes)?;
        let len = map.len();
        let gpa = self.next_tool_gpa;
        let region = kvm_userspace_memory_region {
            slot: self.next_slot,
            flags: KVM_MEM_READONLY,
            guest_phys_addr: gpa,
            memory_size: len as u64,
            userspace_addr: map.addr(),
        };
        unsafe { self.vm.set_user_memory_region(region) }
            .map_err(|e| kvm_err("set_user_memory_region(tool)", e))?;
        self.tools.insert(hash.clone(), (self.next_slot, gpa, len));
        self.next_slot += 1;
        self.next_tool_gpa += len as u64;
        Ok(gpa)
    }

    /// Stop as soon as the guest signals it is doing userspace work, and
    /// timestamp that instant. This is how spawn latency is measured without
    /// the console in the way.
    pub fn stop_at_live_signal(&mut self) {
        self.stop_on_signal = true;
    }

    /// Stop the run the instant the guest prints `marker`, leaving the vCPU at
    /// a clean exit boundary so its state can be captured.
    pub fn stop_when_guest_prints(&mut self, marker: &str) {
        self.stop_marker = Some(marker.as_bytes().to_vec());
    }

    /// Park this booted guest as a [`Mote`] that cells can be forked from.
    ///
    /// Call after a run that stopped at a marker, so the vCPU is at an
    /// instruction boundary with no I/O completion outstanding.
    pub fn park(&self) -> Result<Mote, VmmError> {
        let vcpu = &self.vcpu;
        let ram = self
            ._mem
            .fd
            .clone()
            .ok_or_else(|| VmmError::Backend("guest RAM is not memfd-backed".into()))?;

        let mut msrs = Vec::with_capacity(SNAPSHOT_MSRS.len());
        for &index in SNAPSHOT_MSRS {
            let entry = kvm_bindings::kvm_msr_entry {
                index,
                data: 0,
                ..Default::default()
            };
            let mut buf = kvm_bindings::Msrs::from_entries(&[entry])
                .map_err(|e| VmmError::Backend(format!("Msrs::from_entries: {e:?}")))?;
            // An MSR this host does not implement simply does not travel.
            if vcpu.get_msrs(&mut buf).unwrap_or(0) == 1 {
                msrs.push((index, buf.as_slice()[0].data));
            }
        }

        let mut pic_master = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        let mut pic_slave = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        let mut ioapic = kvm_bindings::kvm_irqchip {
            chip_id: kvm_bindings::KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };
        self.vm
            .get_irqchip(&mut pic_master)
            .map_err(|e| kvm_err("get_irqchip(pic master)", e))?;
        self.vm
            .get_irqchip(&mut pic_slave)
            .map_err(|e| kvm_err("get_irqchip(pic slave)", e))?;
        self.vm
            .get_irqchip(&mut ioapic)
            .map_err(|e| kvm_err("get_irqchip(ioapic)", e))?;

        Ok(Mote {
            ram,
            ram_size: self._mem.len,
            cpuid: self.cpuid.clone(),
            regs: vcpu.get_regs().map_err(|e| kvm_err("get_regs", e))?,
            sregs: vcpu.get_sregs().map_err(|e| kvm_err("get_sregs", e))?,
            fpu: vcpu.get_fpu().map_err(|e| kvm_err("get_fpu", e))?,
            xcrs: vcpu.get_xcrs().map_err(|e| kvm_err("get_xcrs", e))?,
            lapic: vcpu.get_lapic().map_err(|e| kvm_err("get_lapic", e))?,
            events: vcpu
                .get_vcpu_events()
                .map_err(|e| kvm_err("get_vcpu_events", e))?,
            mp_state: vcpu
                .get_mp_state()
                .map_err(|e| kvm_err("get_mp_state", e))?,
            msrs,
            pic_master,
            pic_slave,
            ioapic,
            pit: self.vm.get_pit2().map_err(|e| kvm_err("get_pit2", e))?,
            clock: self.vm.get_clock().map_err(|e| kvm_err("get_clock", e))?,
            serial_lcr: self.serial.lcr,
            serial_ier: self.serial.ier,
            serial_mcr: self.serial.mcr,
            tools: self
                .tools
                .iter()
                .map(|(h, (_, gpa, len))| (h.clone(), *gpa, *len))
                .collect(),
            cfg: self.cfg.clone(),
        })
    }

    /// **Seal a cell from a parked mote.** The hot path the design claims:
    /// no boot, no kernel decompression, no device probe — a copy-on-write
    /// mapping of already-booted RAM plus a vCPU restored to where the mote
    /// was parked.
    pub fn fork_from(mote: &Mote) -> Result<Self, VmmError> {
        Self::fork_from_timed(mote).map(|(c, _)| c)
    }

    /// As [`LinuxCell::fork_from`], reporting where the time went.
    ///
    /// Worth having because the intuition is wrong: the CoW mapping itself is
    /// ~36 µs, and everything else is VM construction and page-fault work. See
    /// `docs/findings/m1-spawn.md`.
    pub fn fork_from_timed(mote: &Mote) -> Result<(Self, ForkTiming), VmmError> {
        let mut t = ForkTiming::default();
        let mark = Instant::now();
        let kvm = Kvm::new().map_err(|e| VmmError::Unsupported(format!("/dev/kvm: {e}")))?;
        let vm = kvm.create_vm().map_err(|e| kvm_err("create_vm", e))?;
        vm.set_identity_map_address(0xfffb_c000)
            .map_err(|e| kvm_err("set_identity_map_address", e))?;
        vm.set_tss_address(0xfffb_d000)
            .map_err(|e| kvm_err("set_tss_address", e))?;
        vm.create_irq_chip()
            .map_err(|e| kvm_err("create_irq_chip", e))?;
        vm.create_pit2(Default::default())
            .map_err(|e| kvm_err("create_pit2", e))?;
        t.create_vm = mark.elapsed();
        let mark = Instant::now();

        // The fork itself: a private view of the mote's RAM.
        let mem = Mem::cow_of(&mote.ram, mote.ram_size)?;
        t.cow_mmap = mark.elapsed();
        let mark = Instant::now();
        let tool_end = TOOL_WINDOW_GPA + TOOL_WINDOW_SIZE;
        for (slot, gpa, len) in [
            (RAM_SLOT_LOW, 0u64, TOOL_WINDOW_GPA),
            (RAM_SLOT_HIGH, tool_end, mote.ram_size as u64 - tool_end),
        ] {
            let region = kvm_userspace_memory_region {
                slot,
                flags: 0,
                guest_phys_addr: gpa,
                memory_size: len,
                userspace_addr: mem.ptr as u64 + gpa,
            };
            unsafe { vm.set_user_memory_region(region) }
                .map_err(|e| kvm_err("set_user_memory_region(RAM)", e))?;
        }

        // Re-lend the same sealed tools, at the same addresses, from the same
        // single host copy.
        let mut tools = HashMap::new();
        let mut next_slot = FIRST_TOOL_SLOT;
        for (hash, gpa, len) in &mote.tools {
            let map = shared_tool_map_existing(hash)
                .ok_or_else(|| VmmError::Backend(format!("tool {hash} no longer held")))?;
            let region = kvm_userspace_memory_region {
                slot: next_slot,
                flags: KVM_MEM_READONLY,
                guest_phys_addr: *gpa,
                memory_size: *len as u64,
                userspace_addr: map.addr(),
            };
            unsafe { vm.set_user_memory_region(region) }
                .map_err(|e| kvm_err("set_user_memory_region(tool)", e))?;
            tools.insert(hash.clone(), (next_slot, *gpa, *len));
            next_slot += 1;
        }

        vm.set_irqchip(&mote.pic_master)
            .map_err(|e| kvm_err("set_irqchip(pic master)", e))?;
        vm.set_irqchip(&mote.pic_slave)
            .map_err(|e| kvm_err("set_irqchip(pic slave)", e))?;
        vm.set_irqchip(&mote.ioapic)
            .map_err(|e| kvm_err("set_irqchip(ioapic)", e))?;
        vm.set_pit2(&mote.pit).map_err(|e| kvm_err("set_pit2", e))?;
        vm.set_clock(&mote.clock)
            .map_err(|e| kvm_err("set_clock", e))?;

        t.memslots = mark.elapsed();
        let mark = Instant::now();
        let vcpu = vm.create_vcpu(0).map_err(|e| kvm_err("create_vcpu", e))?;
        t.create_vcpu = mark.elapsed();
        let mark = Instant::now();
        vcpu.set_cpuid2(&mote.cpuid)
            .map_err(|e| kvm_err("set_cpuid2", e))?;
        for (index, data) in &mote.msrs {
            let entry = kvm_bindings::kvm_msr_entry {
                index: *index,
                data: *data,
                ..Default::default()
            };
            if let Ok(buf) = kvm_bindings::Msrs::from_entries(&[entry]) {
                let _ = vcpu.set_msrs(&buf); // best effort, per MSR
            }
        }
        vcpu.set_sregs(&mote.sregs)
            .map_err(|e| kvm_err("set_sregs", e))?;
        vcpu.set_regs(&mote.regs)
            .map_err(|e| kvm_err("set_regs", e))?;
        vcpu.set_fpu(&mote.fpu).map_err(|e| kvm_err("set_fpu", e))?;
        let _ = vcpu.set_xcrs(&mote.xcrs);
        vcpu.set_lapic(&mote.lapic)
            .map_err(|e| kvm_err("set_lapic", e))?;
        vcpu.set_vcpu_events(&mote.events)
            .map_err(|e| kvm_err("set_vcpu_events", e))?;
        vcpu.set_mp_state(mote.mp_state)
            .map_err(|e| kvm_err("set_mp_state", e))?;
        t.restore_state = mark.elapsed();

        Ok((
            LinuxCell {
                _kvm: kvm,
                vm,
                vcpu,
                _mem: mem,
                serial: Serial {
                    out: Vec::new(),
                    lcr: mote.serial_lcr,
                    ier: mote.serial_ier,
                    mcr: mote.serial_mcr,
                },
                pci_cf8: 0,
                revoke_trigger: None,
                stop_marker: None,
                stop_on_signal: false,
                cpuid: mote.cpuid.clone(),
                tools,
                next_slot,
                next_tool_gpa: TOOL_WINDOW_GPA,
                cfg: mote.cfg.clone(),
            },
            t,
        ))
    }

    /// Arrange to revoke `hash` the instant the guest prints `marker`.
    ///
    /// This is how the kill wire gets tested against a *running* Linux guest
    /// with the tool open and mapped. The guest says when it is holding the
    /// tool; we delete the memslot out from under it mid-run; the guest then
    /// reports what it can still see. Doing it on a marker rather than a timer
    /// means the revocation lands at a known point in the guest's execution
    /// rather than a hopeful one.
    pub fn revoke_when_guest_prints(&mut self, hash: &Hash, marker: &str) {
        self.revoke_trigger = Some((hash.clone(), marker.as_bytes().to_vec()));
    }

    /// Host-side view of a sealed tool's bytes (to assert the seal held).
    pub fn tool_bytes(&self, hash: &Hash, len: usize) -> Option<Vec<u8>> {
        let (_, _, _) = self.tools.get(hash)?;
        shared_tool_bytes(hash, 0, len)
    }

    pub fn tool_gpa(&self, hash: &Hash) -> Option<u64> {
        self.tools.get(hash).map(|&(_, gpa, _)| gpa)
    }

    /// Run the guest until it shuts down or the watchdog fires, collecting
    /// console output.
    pub fn run(&mut self) -> Result<BootReport, VmmError> {
        install_wake_handler();
        let stop = Arc::new(AtomicBool::new(false));
        let tid = unsafe { libc::pthread_self() };
        let watchdog = {
            let stop = stop.clone();
            let timeout = self.cfg.timeout;
            std::thread::spawn(move || {
                let deadline = Instant::now() + timeout;
                while Instant::now() < deadline {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                stop.store(true, Ordering::Relaxed);
                // Interrupt KVM_RUN, repeatedly in case we race the entry.
                for _ in 0..20 {
                    unsafe { libc::pthread_kill(tid, libc::SIGUSR1) };
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        };

        let started = Instant::now();
        let mut exits = 0u64;
        let mut sealed_writes_blocked = 0u64;
        let mut revoked_live = false;
        let mut stop_at_marker = false;
        let mut live_signal_at: Option<Instant> = None;
        let end = loop {
            if stop.load(Ordering::Relaxed) {
                break BootEnd::TimedOut;
            }
            if stop_at_marker {
                break BootEnd::Parked;
            }
            match self.vcpu.run() {
                Ok(exit) => {
                    exits += 1;
                    match exit {
                        VcpuExit::IoOut(port, data) => {
                            if (Serial::BASE..Serial::BASE + 8).contains(&port) {
                                let mut raise = false;
                                for &b in data {
                                    raise |= self.serial.write(port, b);
                                }
                                if raise {
                                    // Pulse IRQ 4 so the driver's TX handler
                                    // runs and feeds us the next byte.
                                    let _ = self.vm.set_irq_line(Serial::IRQ, true);
                                    let _ = self.vm.set_irq_line(Serial::IRQ, false);
                                }
                                // The guest has reached the point we want to
                                // park it at. Stop here, at a clean exit
                                // boundary, so its state can be captured.
                                if self
                                    .stop_marker
                                    .as_ref()
                                    .is_some_and(|m| self.serial.out.ends_with(m))
                                {
                                    stop_at_marker = true;
                                }
                                // The guest has told us it is holding the tool:
                                // pull the pages out from under it, right now.
                                let fire = self
                                    .revoke_trigger
                                    .as_ref()
                                    .is_some_and(|(_, m)| self.serial.out.ends_with(m));
                                if fire {
                                    if let Some((hash, _)) = self.revoke_trigger.take() {
                                        if let Some((slot, gpa, _)) = self.tools.remove(&hash) {
                                            let del = kvm_userspace_memory_region {
                                                slot,
                                                flags: 0,
                                                guest_phys_addr: gpa,
                                                memory_size: 0,
                                                userspace_addr: 0,
                                            };
                                            unsafe { self.vm.set_user_memory_region(del) }
                                                .map_err(|e| kvm_err("revoke memslot", e))?;
                                            revoked_live = true;
                                        }
                                    }
                                }
                            } else if port == PCI_CONFIG_ADDR && data.len() == 4 {
                                self.pci_cf8 =
                                    u32::from_le_bytes(data.try_into().unwrap_or([0; 4]));
                            } else if port == LIVE_SIGNAL_PORT {
                                if live_signal_at.is_none() {
                                    live_signal_at = Some(Instant::now());
                                }
                                if self.stop_on_signal {
                                    stop_at_marker = true;
                                }
                            }
                        }
                        VcpuExit::IoIn(port, data) => {
                            if (Serial::BASE..Serial::BASE + 8).contains(&port) {
                                let v = self.serial.read(port);
                                for b in data.iter_mut() {
                                    *b = v;
                                }
                            } else if port == PCI_CONFIG_ADDR && data.len() == 4 {
                                // Read back what was written, so the kernel
                                // concludes type-1 config access works.
                                data.copy_from_slice(&self.pci_cf8.to_le_bytes());
                            } else {
                                // no device answers: all ones, as on real
                                // hardware. For PCI config data (0xcfc) that
                                // reads as vendor ID 0xffff — "no device here".
                                data.fill(0xff);
                            }
                        }
                        VcpuExit::MmioRead(_, data) => data.fill(0),
                        VcpuExit::MmioWrite(gpa, _) => {
                            // A write that reached us instead of memory. If it
                            // landed in a sealed tool region, stage-2 just
                            // refused a guest write to lent tool code.
                            if self
                                .tools
                                .values()
                                .any(|&(_, base, len)| gpa >= base && gpa < base + len as u64)
                            {
                                sealed_writes_blocked += 1;
                            }
                        }
                        VcpuExit::Hlt => break BootEnd::Halted,
                        VcpuExit::Shutdown | VcpuExit::SystemEvent(_, _) => {
                            break BootEnd::Shutdown
                        }
                        _ => {}
                    }
                }
                Err(e) if e.errno() == libc::EINTR || e.errno() == libc::EAGAIN => {
                    if stop.load(Ordering::Relaxed) {
                        break BootEnd::TimedOut;
                    }
                }
                Err(e) => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = watchdog.join();
                    return Err(kvm_err("KVM_RUN", e));
                }
            }
        };
        stop.store(true, Ordering::Relaxed);
        let _ = watchdog.join();

        Ok(BootReport {
            console: String::from_utf8_lossy(&self.serial.out).into_owned(),
            end,
            exits,
            elapsed: started.elapsed(),
            sealed_writes_blocked,
            revoked_live,
            live_signal_at,
        })
    }
}

/// `boot_params`: the setup header copied from the image, plus what a
/// bootloader is responsible for filling in (loader type, cmdline, initrd,
/// memory map).
fn zero_page(
    image: &BzImage,
    mem_size: usize,
    initrd: Option<(u32, u32)>,
    pmem_bytes: Option<usize>,
) -> Vec<u8> {
    let mut zp = vec![0u8; PAGE];
    zp[HDR_START..HDR_END].copy_from_slice(&image.bytes[HDR_START..HDR_END]);

    zp[HDR_TYPE_OF_LOADER] = 0xff; // undefined/unregistered bootloader
    zp[HDR_LOADFLAGS] |= LOADED_HIGH;
    zp[HDR_CMD_LINE_PTR..HDR_CMD_LINE_PTR + 4].copy_from_slice(&(CMDLINE_GPA as u32).to_le_bytes());
    if let Some((addr, size)) = initrd {
        zp[HDR_RAMDISK_IMAGE..HDR_RAMDISK_IMAGE + 4].copy_from_slice(&addr.to_le_bytes());
        zp[HDR_RAMDISK_SIZE..HDR_RAMDISK_SIZE + 4].copy_from_slice(&size.to_le_bytes());
    }

    // e820. RAM runs either side of the sealed tool window. The window itself
    // is either declared persistent memory — so the nvdimm drivers claim it and
    // a DAX filesystem can be mounted from it — or omitted entirely, in which
    // case it is memory the kernel knows nothing about and never allocates.
    //
    // The PRAM entry must sit *inside* the RAM span for the kernel to register
    // it as a resource; see the note on TOOL_WINDOW_GPA.
    let mut entries = 0u8;
    let push = |zp: &mut Vec<u8>, n: &mut u8, addr: u64, size: u64, kind: u32| {
        let off = BP_E820_TABLE + (*n as usize) * 20;
        zp[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        zp[off + 8..off + 16].copy_from_slice(&size.to_le_bytes());
        zp[off + 16..off + 20].copy_from_slice(&kind.to_le_bytes());
        *n += 1;
    };
    let tool_end = TOOL_WINDOW_GPA + TOOL_WINDOW_SIZE;
    push(&mut zp, &mut entries, 0, EBDA_GPA, E820_RAM);
    push(
        &mut zp,
        &mut entries,
        KERNEL_GPA,
        TOOL_WINDOW_GPA - KERNEL_GPA,
        E820_RAM,
    );
    if let Some(len) = pmem_bytes {
        push(
            &mut zp,
            &mut entries,
            TOOL_WINDOW_GPA,
            len as u64,
            E820_PRAM,
        );
    }
    push(
        &mut zp,
        &mut entries,
        tool_end,
        mem_size as u64 - tool_end,
        E820_RAM,
    );
    zp[BP_E820_ENTRIES] = entries;
    zp
}

/// Flat 64-bit GDT. The protocol mandates __BOOT_CS = 0x10 (exec/read) and
/// __BOOT_DS = 0x18 (read/write), both 4 GiB flat.
fn boot_gdt() -> Vec<u8> {
    let mut gdt = vec![0u8; 16]; // entries 0 and 1 unused
    gdt.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0x9a, 0xaf, 0]); // 0x10 code64 (L=1)
    gdt.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0x92, 0xcf, 0]); // 0x18 data
    gdt
}

/// Identity-map the first GiB with 2 MiB pages — enough to carry the kernel to
/// the point where it installs its own tables.
fn write_page_tables(mem: &Mem) -> Result<(), VmmError> {
    mem.write(PML4_GPA, &(PDPT_GPA | PDE_PRESENT | PDE_RW).to_le_bytes())?;
    mem.write(PDPT_GPA, &(PD_GPA | PDE_PRESENT | PDE_RW).to_le_bytes())?;
    let mut pd = Vec::with_capacity(512 * 8);
    for i in 0..512u64 {
        pd.extend_from_slice(&((i << 21) | PDE_PRESENT | PDE_RW | PDE_PS).to_le_bytes());
    }
    mem.write(PD_GPA, &pd)
}

/// Put the vCPU in 64-bit long mode with the segment state the protocol wants.
fn set_long_mode(vcpu: &VcpuFd) -> Result<(), VmmError> {
    let mut sregs = vcpu.get_sregs().map_err(|e| kvm_err("get_sregs", e))?;

    sregs.cs.base = 0;
    sregs.cs.limit = 0xffff_ffff;
    sregs.cs.selector = SEL_CODE;
    sregs.cs.type_ = 0b1011; // execute/read, accessed
    sregs.cs.present = 1;
    sregs.cs.dpl = 0;
    sregs.cs.db = 0;
    sregs.cs.s = 1;
    sregs.cs.l = 1; // 64-bit
    sregs.cs.g = 1;

    for seg in [
        &mut sregs.ds,
        &mut sregs.es,
        &mut sregs.fs,
        &mut sregs.gs,
        &mut sregs.ss,
    ] {
        seg.base = 0;
        seg.limit = 0xffff_ffff;
        seg.selector = SEL_DATA;
        seg.type_ = 0b0011; // read/write, accessed
        seg.present = 1;
        seg.dpl = 0;
        seg.db = 1;
        seg.s = 1;
        seg.l = 0;
        seg.g = 1;
    }

    sregs.gdt.base = GDT_GPA;
    sregs.gdt.limit = (boot_gdt().len() - 1) as u16;

    sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    sregs.cr3 = PML4_GPA;
    sregs.cr4 = CR4_PAE;
    sregs.efer = EFER_LME | EFER_LMA;

    vcpu.set_sregs(&sregs).map_err(|e| kvm_err("set_sregs", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel_or_skip() -> Option<PathBuf> {
        if !Path::new("/dev/kvm").exists() {
            eprintln!("skipping: no /dev/kvm");
            return None;
        }
        match BootConfig::host_kernel() {
            Some(k) => Some(k),
            None => {
                eprintln!("skipping: no readable /boot/vmlinuz-* on this host");
                None
            }
        }
    }

    #[test]
    fn parses_a_real_bzimage() {
        let Some(kernel) = kernel_or_skip() else {
            return;
        };
        let img = BzImage::load(&kernel).unwrap();
        assert!(img.init_size() > 0);
        assert!(!img.protected_mode_kernel().is_empty());
    }

    /// The guest reaches real userspace and our init runs there. Skips (does
    /// not fail) if the initramfs has not been built — `make initramfs`.
    #[test]
    fn guest_init_runs_in_userspace() {
        let Some(kernel) = kernel_or_skip() else {
            return;
        };
        let Some(initrd) = BootConfig::built_initramfs() else {
            eprintln!("skipping: no target/nous-initramfs.cpio — run `make initramfs`");
            return;
        };
        let mut cell = LinuxCell::boot(BootConfig::new(&kernel).with_initrd(initrd)).unwrap();
        let r = cell.run().unwrap();
        assert!(
            r.guest_init_ran(),
            "guest init never reported in; console tail:\n{}",
            r.tail(30)
        );
        assert_eq!(
            r.guest_report("mmap_anon"),
            Some("ok"),
            "guest userspace could not mmap"
        );
        assert_eq!(
            r.end,
            BootEnd::Shutdown,
            "init should reboot cleanly, not time out"
        );
    }

    #[test]
    fn boots_a_stock_kernel_to_userspace_handoff() {
        let Some(kernel) = kernel_or_skip() else {
            return;
        };
        let mut cell = LinuxCell::boot(BootConfig::new(&kernel)).unwrap();
        let r = cell.run().unwrap();
        eprintln!(
            "--- console ({} bytes, {} exits, {:?}, end {:?}) ---\n{}",
            r.console.len(),
            r.exits,
            r.elapsed,
            r.end,
            r.head(25)
        );
        assert!(
            r.reached_kernel(),
            "kernel never announced itself; console was:\n{}",
            r.console
        );
        assert!(
            r.reached_userspace_handoff(),
            "kernel did not reach userspace hand-off; console tail:\n{}",
            r.console
        );
    }

    /// The VFS↔memslot join, in the form that matters: a **guest userspace
    /// process** maps the sealed region and tries to modify it.
    ///
    /// Three things have to be true at once, and each rules out a different
    /// way of being fooled:
    ///   * the magic matches — we mapped the sealed page-set, not a copy or
    ///     a zero page;
    ///   * the guest *executes* code out of the mapping — the pages are
    ///     genuinely r-x to a real process, not merely readable;
    ///   * the guest's write does not land, and the host counts the refusal —
    ///     the seal governs the mapping, which is the whole claim.
    #[test]
    fn guest_userspace_mapping_of_a_sealed_tool_is_the_real_thing() {
        let Some(kernel) = kernel_or_skip() else {
            return;
        };
        let Some(initrd) = BootConfig::built_initramfs() else {
            eprintln!("skipping: no target/nous-initramfs.cpio — run `make initramfs`");
            return;
        };
        let mut cell = LinuxCell::boot(BootConfig::new(&kernel).with_initrd(initrd)).unwrap();
        let tool = probe_tool();
        let h = Hash::of(&tool);
        let gpa = cell.seal_tool(&h, &tool).unwrap();
        assert_eq!(
            gpa, TOOL_WINDOW_GPA,
            "guest init hardcodes this address; keep them in step"
        );

        let r = cell.run().unwrap();
        assert!(r.guest_init_ran(), "console tail:\n{}", r.tail(30));

        match r.guest_report("seal_probe") {
            Some("mapped") => {}
            other => {
                eprintln!(
                    "guest could not map the sealed region ({other:?}); \
                     this host's kernel may forbid the mapping path"
                );
                return;
            }
        }

        assert_eq!(
            r.guest_report("tool_magic"),
            Some("match"),
            "guest mapped something, but not the sealed page-set"
        );
        assert_eq!(
            r.guest_report("tool_exec"),
            Some("ok"),
            "guest could not execute out of the sealed mapping"
        );
        assert_eq!(
            r.guest_report("seal_write_landed"),
            Some("no"),
            "A GUEST USERSPACE WRITE MODIFIED LENT TOOL CODE — claim C1 does not \
             survive this mapping path"
        );
        assert!(
            r.sealed_writes_blocked > 0,
            "host saw no refused write; the guest's account is unconfirmed"
        );
        assert_eq!(
            cell.tool_bytes(&h, tool.len()).unwrap(),
            tool,
            "sealed bytes changed"
        );
    }

    /// The built tool filesystem image (`make toolfs`), if it is there.
    fn built_toolfs() -> Option<PathBuf> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .map(|root| root.join("target/nous-toolfs.img"))?;
        p.exists().then_some(p)
    }

    /// The join in its production shape: a guest opens a tool **by path** and
    /// maps it, and the sealed pages are what it gets.
    ///
    /// The chain under test is the real one: the sealed region is declared to
    /// the kernel as persistent memory, the nvdimm drivers turn it into
    /// /dev/pmem0, and an ext2 image inside it is mounted with `dax=always` —
    /// DAX meaning "map the file's pages directly, not through the page cache".
    ///
    /// The write is what separates direct from copied. A page-cache copy would
    /// absorb it silently, leaving the byte changed and the host counting no
    /// refusal; a direct mapping puts the store against a read-only memslot,
    /// where hardware refuses it. Magic and execution alone pass either way.
    #[test]
    fn guest_opens_a_tool_by_path_and_gets_the_sealed_pages() {
        let Some(kernel) = kernel_or_skip() else {
            return;
        };
        let Some(initrd) = BootConfig::built_initramfs() else {
            eprintln!("skipping: no initramfs — run `make initramfs`");
            return;
        };
        let Some(toolfs) = built_toolfs() else {
            eprintln!("skipping: no target/nous-toolfs.img — run `make toolfs`");
            return;
        };
        if BootConfig::modules_dir_for(&kernel).is_none() {
            eprintln!("skipping: no /lib/modules for {}", kernel.display());
            return;
        }

        let image = std::fs::read(&toolfs).unwrap();
        assert!(
            image.windows(8).any(|w| w == PROBE_MAGIC),
            "tool filesystem image does not contain the probe magic"
        );

        let cfg = BootConfig::new(&kernel)
            .with_initrd(initrd)
            .with_pmem(image.len());
        let mut cell = LinuxCell::boot(cfg).unwrap();
        let h = Hash::of(&image);
        let gpa = cell.seal_tool(&h, &image).unwrap();
        assert_eq!(gpa, TOOL_WINDOW_GPA, "pmem cmdline names this address");
        // Beat 5 of the five-beat proof, against a real kernel: revoke while
        // the guest holds the tool open and mapped.
        cell.revoke_when_guest_prints(&h, "NOUS:dax_revoke_ready=now");

        let r = cell.run().unwrap();
        assert!(r.guest_init_ran(), "console tail:\n{}", r.tail(30));

        // What the kernel itself said about the pmem chain. Captured because
        // when this breaks, the guest can only report "no device" while the
        // reason is always in the kernel log.
        eprintln!("--- kernel, on the pmem chain ---");
        for l in r.console.lines().filter(|l| {
            let l = l.to_ascii_lowercase();
            [
                "pmem",
                "nvdimm",
                "e820",
                "persistent",
                "user:",
                "trim",
                "remov",
                "last_pfn",
            ]
            .iter()
            .any(|k| l.contains(k))
        }) {
            eprintln!("{l}");
        }

        // Each stage of the chain reports, so a failure says which link broke
        // rather than just "the join does not work".
        for (key, want) in [
            ("dax_pmem", "present"),
            ("dax_mount", "ok"),
            ("dax_open", "ok"),
            ("dax_mmap", "ok"),
        ] {
            let got = r.guest_report(key);
            assert_eq!(
                got,
                Some(want),
                "DAX chain broke at {key} (got {got:?}); guest said: {}",
                r.console
                    .lines()
                    .filter(|l| l.contains("NOUS:"))
                    .collect::<Vec<_>>()
                    .join(" | ")
            );
        }

        assert_eq!(
            r.guest_report("dax_magic"),
            Some("match"),
            "mapped the file, but not the sealed page-set"
        );
        assert_eq!(
            r.guest_report("dax_exec"),
            Some("ok"),
            "could not execute out of the file mapping"
        );
        assert_eq!(
            r.guest_report("dax_write_landed"),
            Some("no"),
            "A WRITE THROUGH THE FILE MAPPING MODIFIED LENT TOOL CODE — either \
             the mapping is a page-cache copy, or the seal does not govern it"
        );
        assert!(
            r.sealed_writes_blocked > 0,
            "host counted no refused write; the mapping is not reaching the \
             sealed memslot (a page-cache copy would look exactly like this)"
        );

        // Revocation reaches a running guest through the file mapping: the
        // memslot was deleted while the guest held the tool open, and what it
        // could see afterwards was not the tool.
        assert!(r.revoked_live, "the revocation trigger never fired");
        assert_eq!(
            r.guest_report("dax_after_revoke"),
            Some("revoked"),
            "a revoked tool was still readable through the guest's existing \
             mapping — revocation does not reach a running cell"
        );
        // The whole image, not its first bytes: an ext2 image opens with a
        // 1024-byte boot block, so offset 0 is legitimately zeros and the
        // magic lives inside the /probe file's data block.
        //
        // Read through the shared registry rather than the cell: the cell no
        // longer maps this hash — that is what revocation means — while the
        // host page-set it lent is still there to be checked.
        assert_eq!(
            shared_tool_bytes(&h, 0, image.len()).unwrap(),
            image,
            "the sealed filesystem image changed"
        );
    }

    /// **The thesis, tested.** "The guest never boots in the hot path — spawn
    /// is a CoW fork of a warm mote."
    ///
    /// Everything before this was a fork of a 16 KiB hand-assembled toy, which
    /// says nothing about whether a *real* guest can be forked. Here a stock
    /// Linux kernel boots once, is parked at a known instruction in userspace,
    /// and cells are forked from it. Each cell must resume in userspace and do
    /// work without booting anything.
    #[test]
    fn cells_fork_from_a_booted_kernel_without_booting() {
        let Some(kernel) = kernel_or_skip() else {
            return;
        };
        let Some(initrd) = BootConfig::built_initramfs() else {
            eprintln!("skipping: no initramfs — run `make initramfs`");
            return;
        };

        // Boot once. This is the slow part, and it happens off the hot path.
        let mut template = LinuxCell::boot(BootConfig::new(&kernel).with_initrd(initrd)).unwrap();
        template.stop_when_guest_prints("NOUS:mote=parked");
        let boot = template.run().unwrap();
        assert_eq!(
            boot.end,
            BootEnd::Parked,
            "template did not reach the park point; tail:\n{}",
            boot.tail(20)
        );
        assert!(boot.guest_init_ran());
        let mote = template.park().unwrap();

        // Now the hot path: fork cells from the parked mote.
        for i in 0..3 {
            let mut cell = LinuxCell::fork_from(&mote).unwrap();
            cell.stop_when_guest_prints("NOUS:cell=live");
            let r = cell.run().unwrap();
            assert!(
                r.cell_went_live(),
                "cell {i} never reached userspace after the fork; \
                 ended {:?}, console:\n{}",
                r.end,
                r.console
            );
            // It resumed — it did not boot. A booting guest would have
            // announced itself again.
            assert!(
                !r.console.contains("Linux version"),
                "cell {i} booted a kernel; this is supposed to be a fork"
            );
        }
    }

    /// The sealed region must be present in a *real* kernel's physical address
    /// space, and the kernel booting normally must not disturb it.
    #[test]
    fn sealed_tool_survives_a_real_kernel_boot() {
        let Some(kernel) = kernel_or_skip() else {
            return;
        };
        let mut cell = LinuxCell::boot(BootConfig::new(&kernel)).unwrap();
        let tool = b"attested tool bytes that no guest may modify".to_vec();
        let h = Hash::of(&tool);
        let gpa = cell.seal_tool(&h, &tool).unwrap();
        assert!(gpa >= TOOL_WINDOW_GPA);

        let r = cell.run().unwrap();
        assert!(r.reached_kernel());
        assert_eq!(
            cell.tool_bytes(&h, tool.len()).unwrap(),
            tool,
            "a full kernel boot must not alter sealed tool bytes"
        );
    }
}
