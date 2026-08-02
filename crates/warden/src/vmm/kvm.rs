//! Real KVM backend — M1 (fork path) and the sealing half of M2, driving a
//! genuine microVM via `/dev/kvm`.
//!
//! What is REAL here — enforced by hardware, below the guest, verifiable by the
//! feature-gated tests, `nous-demo-kvm` and `nous-bench-kvm`:
//!
//! * **fork_from_snapshot** — guest RAM is a `MAP_PRIVATE` (copy-on-write)
//!   mapping of a shared per-snapshot template memfd. Forked cells share clean
//!   pages; a write in one cell never appears in another or in the template.
//!   Measured: ~1,000 cells, fork p99 well under the 5 ms gate.
//! * **map_pages_ro_exec** — tool pages enter the guest as `KVM_MEM_READONLY`
//!   memslots, backed by **one host allocation per tool hash shared across all
//!   cells**. The guest can read and *execute* them; a guest write does not
//!   touch the page — the CPU exits to the host (`KVM_EXIT_MMIO`) instead.
//!   This is stage-2 sealing, and it holds against a guest that installs its
//!   own page tables marking the page writable (see the hostile-guest test):
//!   no guest-side state, kernel or not, can undo it. That is claim C1.
//! * **unmap** — deleting the memslot revokes the pages from a *running* guest;
//!   subsequent access observes unmapped memory, not the tool.
//! * **freeze_readonly** — RAM is re-slotted read-only; the guest can no longer
//!   write anything, while the host still reads the workspace for harvest.
//!
//! What is NOT here yet: a stripped mote kernel and in-guest pilot (M5), and
//! the VFS↔memslot join (ADR-0005) that a real guest needs so an `mmap` of
//! `/tools/python` lands on the sealed memslot rather than a page-cache copy.
//! The guest in this slice runs hand-assembled flat real-mode / 32-bit code so
//! the hardware properties are provable without booting a kernel; only tools
//! mapped below [`REALMODE_LIMIT`] are reachable by those programs.

use super::{Vmm, VmmError};
use kvm_bindings::{kvm_userspace_memory_region, KVM_MEM_READONLY};
use kvm_ioctls::{Cap, Kvm, VcpuExit, VcpuFd, VmFd};
use nous_manifest::Hash;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex, OnceLock};

/// One 4 KiB page.
pub const PAGE: usize = 4096;
/// Guest RAM: 16 KiB at GPA 0. Flat real-mode layout: entry code at [`ENTRY`],
/// scratch at [`SCRATCH`], stack below 0x3f00, template marker at [`MARK_OFF`].
pub const RAM_SIZE: usize = 0x4000;
/// Guest code entry point inside RAM.
pub const ENTRY: u64 = 0x1000;
/// Scratch byte the proof programs write observations to.
pub const SCRATCH: u16 = 0x2000;
/// Offset where a mote template carries its marker (the CoW proof reads it).
pub const MARK_OFF: usize = 0x0f00;
/// Tool pages are mapped from this GPA upward.
pub const TOOL_GPA_BASE: u64 = 0x4000;
/// The 64 KiB a flat real-mode guest can address. Tools may be mapped above
/// this (nothing stops it, and the density benchmarks do), but only tools
/// below it are reachable by the kernel-less M1/M2 guest programs.
pub const REALMODE_LIMIT: u64 = 0x1_0000;
/// Scratch region for the hostile-guest proof: its page tables and 32-bit
/// code. Sits at 3 MiB — inside the 4 MiB that guest identity-maps.
pub const SCRATCH_GPA: u64 = 0x30_0000;
/// Size of that scratch region.
pub const SCRATCH_SIZE: usize = 0x4000;

const RAM_SLOT: u32 = 0;
const SCRATCH_SLOT: u32 = 1;
const MAX_EXITS: usize = 10_000;

/// The marker bytes a template for `snapshot` carries at [`MARK_OFF`].
pub fn template_marker(snapshot: &str) -> Vec<u8> {
    format!("NOUSMOTE:{snapshot}").into_bytes()
}

fn errno(what: &str) -> VmmError {
    VmmError::Backend(format!("{what}: {}", std::io::Error::last_os_error()))
}

fn kvm_err(what: &str, e: kvm_ioctls::Error) -> VmmError {
    VmmError::Backend(format!("{what}: {e}"))
}

/// Process-global registry of warm mote templates, one memfd per snapshot
/// name. In the full design this image is produced by assay (stripped
/// kernel + pilot, pre-booted and parked); here it is a deterministic RAM
/// image so the CoW fork mechanics are real while the content is minimal.
fn registry() -> &'static Mutex<HashMap<String, Arc<OwnedFd>>> {
    static REG: OnceLock<Mutex<HashMap<String, Arc<OwnedFd>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn template_for(snapshot: &str) -> Result<Arc<OwnedFd>, VmmError> {
    let mut reg = registry().lock().expect("template registry poisoned");
    if let Some(fd) = reg.get(snapshot) {
        return Ok(fd.clone());
    }
    let cname = CString::new(format!("nous-mote-{snapshot}"))
        .map_err(|_| VmmError::Backend("snapshot name contains NUL".into()))?;
    let raw = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC) };
    if raw < 0 {
        return Err(errno("memfd_create"));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::ftruncate(fd.as_raw_fd(), RAM_SIZE as libc::off_t) } != 0 {
        return Err(errno("ftruncate template"));
    }
    let mark = template_marker(snapshot);
    let n = unsafe {
        libc::pwrite(
            fd.as_raw_fd(),
            mark.as_ptr() as *const libc::c_void,
            mark.len(),
            MARK_OFF as libc::off_t,
        )
    };
    if n != mark.len() as isize {
        return Err(errno("pwrite template marker"));
    }
    let fd = Arc::new(fd);
    reg.insert(snapshot.to_string(), fd.clone());
    Ok(fd)
}

/// Process-global registry of tool page-sets: **one host allocation per tool
/// hash, shared by every cell that loans it**. This is the density claim in
/// code — N cells running the same CPython map the same physical pages, and
/// because they map read-only, sharing is safe. A tool map is written once at
/// creation, before it is published here, and is read-only thereafter.
fn tool_registry() -> &'static Mutex<HashMap<Hash, Arc<HostMap>>> {
    static REG: OnceLock<Mutex<HashMap<Hash, Arc<HostMap>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get (or create) the single shared page-set for `hash`.
fn shared_tool(hash: &Hash, bytes: &[u8]) -> Result<Arc<HostMap>, VmmError> {
    let mut reg = tool_registry().lock().expect("tool registry poisoned");
    if let Some(map) = reg.get(hash) {
        return Ok(map.clone());
    }
    let len = bytes.len().div_ceil(PAGE).max(1) * PAGE;
    let map = HostMap::map_anon(len)?;
    map.write(0, bytes)?; // the only write; read-only once published
    let map = Arc::new(map);
    reg.insert(hash.clone(), map.clone());
    Ok(map)
}

/// How many distinct tool page-sets the host is currently holding.
pub fn shared_tool_count() -> usize {
    tool_registry().lock().map(|r| r.len()).unwrap_or(0)
}

/// The shared page-set for `hash`, creating it from `bytes` if this is the
/// first cell to loan it. Other backends (e.g. [`super::boot::LinuxCell`]) go
/// through here so every cell in the process maps one physical copy.
pub fn shared_tool_map(hash: &Hash, bytes: &[u8]) -> Result<SharedTool, VmmError> {
    shared_tool(hash, bytes).map(SharedTool)
}

/// The shared page-set for `hash`, if some cell already lent it. Used when
/// forking a mote: the tools it was holding are re-lent from the same copy,
/// never re-created.
pub fn shared_tool_map_existing(hash: &Hash) -> Option<SharedTool> {
    tool_registry()
        .lock()
        .ok()?
        .get(hash)
        .cloned()
        .map(SharedTool)
}

/// Host-side read of a shared tool's bytes, for asserting the seal held.
pub fn shared_tool_bytes(hash: &Hash, off: usize, len: usize) -> Option<Vec<u8>> {
    tool_registry()
        .lock()
        .ok()?
        .get(hash)
        .and_then(|m| m.read(off, len).ok())
}

/// A handle to one shared tool page-set: a host mapping every cell that loans
/// this hash points at.
pub struct SharedTool(Arc<HostMap>);

impl SharedTool {
    /// Host virtual address to hand to `KVM_SET_USER_MEMORY_REGION`.
    pub fn addr(&self) -> u64 {
        self.0.ptr as u64
    }

    /// Page-aligned length of the mapping.
    pub fn len(&self) -> usize {
        self.0.len
    }

    pub fn is_empty(&self) -> bool {
        self.0.len == 0
    }
}

/// A host-side mmap the guest sees as physical memory. Unmapped on drop.
struct HostMap {
    ptr: *mut u8,
    len: usize,
}

// The raw pointer is to memory this struct exclusively owns.
unsafe impl Send for HostMap {}
// Shared tool maps are published read-only (written once before sharing), so
// concurrent access from several cells observes immutable bytes.
unsafe impl Sync for HostMap {}

impl HostMap {
    /// CoW view of a template: private mapping, shared clean pages.
    fn map_private_of(fd: &OwnedFd, len: usize) -> Result<Self, VmmError> {
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
            return Err(errno("mmap template (CoW)"));
        }
        Ok(HostMap {
            ptr: ptr as *mut u8,
            len,
        })
    }

    fn map_anon(len: usize) -> Result<Self, VmmError> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(errno("mmap anonymous"));
        }
        Ok(HostMap {
            ptr: ptr as *mut u8,
            len,
        })
    }

    fn read(&self, off: usize, len: usize) -> Result<Vec<u8>, VmmError> {
        if off.checked_add(len).map_or(true, |end| end > self.len) {
            return Err(VmmError::Backend(format!(
                "read [{off}, {off}+{len}) outside mapping of {} bytes",
                self.len
            )));
        }
        let mut out = vec![0u8; len];
        unsafe { std::ptr::copy_nonoverlapping(self.ptr.add(off), out.as_mut_ptr(), len) };
        Ok(out)
    }

    fn write(&self, off: usize, bytes: &[u8]) -> Result<(), VmmError> {
        if off
            .checked_add(bytes.len())
            .map_or(true, |end| end > self.len)
        {
            return Err(VmmError::Backend(format!(
                "write [{off}, {off}+{}) outside mapping of {} bytes",
                bytes.len(),
                self.len
            )));
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(off), bytes.len()) };
        Ok(())
    }
}

impl Drop for HostMap {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

struct Tool {
    map: Arc<HostMap>,
    slot: u32,
    gpa: u64,
    len: usize,
}

/// A hardware-observed event from a guest run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestEvent {
    /// The guest tried to WRITE a sealed page (a tool page, or RAM after
    /// freeze). The write never reached memory — stage-2 made the CPU exit to
    /// the host instead.
    SealedWriteBlocked { gpa: u64 },
    /// The guest read a GPA with no memslot behind it (e.g. a revoked,
    /// unmapped tool). The read observes zeros.
    UnmappedRead { gpa: u64 },
    /// The guest wrote a GPA with no memslot behind it.
    UnmappedWrite { gpa: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunEnd {
    /// The guest program ran to its HLT.
    Halted,
    /// The guest triple-faulted (a bug in the guest program).
    Shutdown,
}

/// Outcome of one guest run: how it ended, plus every seal/unmap event the
/// hardware surfaced along the way.
#[derive(Debug)]
pub struct RunReport {
    pub end: RunEnd,
    pub events: Vec<GuestEvent>,
}

/// Drives one real microVM via `/dev/kvm`. 1 warden : 1 microVM : 1 cell.
pub struct KvmVmm {
    kvm: Kvm,
    vm: Option<VmFd>,
    vcpu: Option<VcpuFd>,
    ram: Option<HostMap>,
    ram_frozen: bool,
    tools: HashMap<Hash, Tool>,
    /// Optional writable region above the real-mode window (page tables and
    /// 32-bit code for the hostile-guest proof).
    scratch: Option<HostMap>,
    next_slot: u32,
    next_gpa: u64,
}

impl KvmVmm {
    /// Open `/dev/kvm`. Fails with `Unsupported` when the device or the
    /// read-only-memslot capability is missing — it never silently degrades.
    pub fn new() -> Result<Self, VmmError> {
        let kvm =
            Kvm::new().map_err(|e| VmmError::Unsupported(format!("/dev/kvm unavailable: {e}")))?;
        if !kvm.check_extension(Cap::ReadonlyMem) {
            return Err(VmmError::Unsupported(
                "KVM_CAP_READONLY_MEM missing — cannot seal tool pages".into(),
            ));
        }
        Ok(KvmVmm {
            kvm,
            vm: None,
            vcpu: None,
            ram: None,
            ram_frozen: false,
            tools: HashMap::new(),
            scratch: None,
            next_slot: SCRATCH_SLOT + 1,
            next_gpa: TOOL_GPA_BASE,
        })
    }

    fn vm(&self) -> Result<&VmFd, VmmError> {
        self.vm
            .as_ref()
            .ok_or_else(|| VmmError::Backend("no VM — call fork_from_snapshot first".into()))
    }

    fn ram(&self) -> Result<&HostMap, VmmError> {
        self.ram
            .as_ref()
            .ok_or_else(|| VmmError::Backend("no RAM — call fork_from_snapshot first".into()))
    }

    fn set_region(
        vm: &VmFd,
        slot: u32,
        gpa: u64,
        size: usize,
        addr: u64,
        flags: u32,
    ) -> Result<(), VmmError> {
        let region = kvm_userspace_memory_region {
            slot,
            flags,
            guest_phys_addr: gpa,
            memory_size: size as u64,
            userspace_addr: addr,
        };
        unsafe { vm.set_user_memory_region(region) }
            .map_err(|e| kvm_err(&format!("set_user_memory_region(slot {slot})"), e))
    }

    /// Give the guest a writable region at [`SCRATCH_GPA`], above the
    /// real-mode window. The hostile-guest proof parks its page tables and
    /// 32-bit code here — memory the guest fully controls, so that when its
    /// write to a *sealed* page still fails, nothing guest-side can be blamed.
    pub fn map_scratch_rw(&mut self, image: &[u8]) -> Result<u64, VmmError> {
        if self.scratch.is_some() {
            return Err(VmmError::Backend("scratch region already mapped".into()));
        }
        if image.len() > SCRATCH_SIZE {
            return Err(VmmError::Backend(format!(
                "scratch image {} bytes exceeds region {SCRATCH_SIZE}",
                image.len()
            )));
        }
        let map = HostMap::map_anon(SCRATCH_SIZE)?;
        map.write(0, image)?;
        Self::set_region(
            self.vm()?,
            SCRATCH_SLOT,
            SCRATCH_GPA,
            SCRATCH_SIZE,
            map.ptr as u64,
            0,
        )?;
        self.scratch = Some(map);
        Ok(SCRATCH_GPA)
    }

    /// Host-side read of the scratch region (to inspect what the guest did).
    pub fn read_scratch(&self, off: usize, len: usize) -> Result<Vec<u8>, VmmError> {
        self.scratch
            .as_ref()
            .ok_or_else(|| VmmError::Backend("no scratch region mapped".into()))?
            .read(off, len)
    }

    /// Host-side read of guest RAM (workspace harvest — allowed in every phase).
    pub fn read_ram(&self, off: usize, len: usize) -> Result<Vec<u8>, VmmError> {
        self.ram()?.read(off, len)
    }

    /// Host-side write into guest RAM (warden hydrating the workspace in P1,
    /// and the proof harness placing guest programs).
    pub fn write_ram(&mut self, off: usize, bytes: &[u8]) -> Result<(), VmmError> {
        self.ram()?.write(off, bytes)
    }

    /// The GPA a mapped tool was sealed at, if it is currently mapped.
    pub fn tool_gpa(&self, hash: &Hash) -> Option<u64> {
        self.tools.get(hash).map(|t| t.gpa)
    }

    /// Host-side view of a sealed tool page (for asserting the seal held).
    pub fn tool_bytes(&self, hash: &Hash, off: usize, len: usize) -> Option<Vec<u8>> {
        self.tools.get(hash).and_then(|t| t.map.read(off, len).ok())
    }

    /// Run the vCPU from `entry` (flat real mode) until HLT, collecting every
    /// seal/unmap event the hardware surfaces. Blocked writes do not stop the
    /// guest — the write is simply lost and execution continues, which is
    /// exactly the property the tests assert.
    pub fn run_guest(&mut self, entry: u64) -> Result<RunReport, VmmError> {
        // Sealed/mapped ranges snapshot, for classifying MMIO exits.
        let tool_ranges: Vec<(u64, u64)> = self
            .tools
            .values()
            .map(|t| (t.gpa, t.gpa + t.len as u64))
            .collect();
        let ram_frozen = self.ram_frozen;

        let vcpu = self
            .vcpu
            .as_mut()
            .ok_or_else(|| VmmError::Backend("no vCPU — call fork_from_snapshot first".into()))?;

        let mut regs = vcpu.get_regs().map_err(|e| kvm_err("get_regs", e))?;
        regs.rip = entry;
        regs.rflags = 2; // reserved bit; interrupts disabled
        regs.rsp = 0x3f00;
        vcpu.set_regs(&regs).map_err(|e| kvm_err("set_regs", e))?;

        let mut events = Vec::new();
        for _ in 0..MAX_EXITS {
            match vcpu.run().map_err(|e| kvm_err("KVM_RUN", e))? {
                VcpuExit::Hlt => {
                    return Ok(RunReport {
                        end: RunEnd::Halted,
                        events,
                    })
                }
                VcpuExit::MmioWrite(gpa, _data) => {
                    let sealed = tool_ranges.iter().any(|&(s, e)| gpa >= s && gpa < e)
                        || (ram_frozen && gpa < RAM_SIZE as u64);
                    events.push(if sealed {
                        GuestEvent::SealedWriteBlocked { gpa }
                    } else {
                        GuestEvent::UnmappedWrite { gpa }
                    });
                }
                VcpuExit::MmioRead(gpa, data) => {
                    data.fill(0);
                    events.push(GuestEvent::UnmappedRead { gpa });
                }
                VcpuExit::Shutdown => {
                    return Ok(RunReport {
                        end: RunEnd::Shutdown,
                        events,
                    })
                }
                other => {
                    return Err(VmmError::Backend(format!(
                        "unexpected vcpu exit: {other:?}"
                    )))
                }
            }
        }
        Err(VmmError::Backend(
            "guest exceeded exit budget without halting".into(),
        ))
    }
}

impl Vmm for KvmVmm {
    fn fork_from_snapshot(&mut self, snapshot: &str) -> Result<(), VmmError> {
        if self.vm.is_some() {
            return Err(VmmError::Backend(
                "cell already forked — one warden drives one microVM".into(),
            ));
        }
        let template = template_for(snapshot)?;
        // The fork itself: a private (CoW) mapping of the warm template.
        let ram = HostMap::map_private_of(&template, RAM_SIZE)?;

        let vm = self.kvm.create_vm().map_err(|e| kvm_err("create_vm", e))?;
        vm.set_tss_address(0xfffb_d000)
            .map_err(|e| kvm_err("set_tss_address", e))?;
        Self::set_region(&vm, RAM_SLOT, 0, RAM_SIZE, ram.ptr as u64, 0)?;

        let vcpu = vm.create_vcpu(0).map_err(|e| kvm_err("create_vcpu", e))?;
        let mut sregs = vcpu.get_sregs().map_err(|e| kvm_err("get_sregs", e))?;
        for seg in [
            &mut sregs.cs,
            &mut sregs.ds,
            &mut sregs.es,
            &mut sregs.ss,
            &mut sregs.fs,
            &mut sregs.gs,
        ] {
            seg.base = 0;
            seg.selector = 0;
        }
        vcpu.set_sregs(&sregs)
            .map_err(|e| kvm_err("set_sregs", e))?;

        self.vm = Some(vm);
        self.vcpu = Some(vcpu);
        self.ram = Some(ram);
        Ok(())
    }

    fn map_pages_ro_exec(&mut self, hash: &Hash, bytes: &[u8]) -> Result<(), VmmError> {
        if self.tools.contains_key(hash) {
            return Ok(()); // already sealed in — idempotent
        }
        // One host allocation per tool hash, shared across every cell that
        // loans it — the physical copy is not duplicated per cell.
        let map = shared_tool(hash, bytes)?;
        let len = map.len;
        // Sequential GPAs, stepping over the scratch region if it is in the way.
        let mut gpa = self.next_gpa;
        let scratch_end = SCRATCH_GPA + SCRATCH_SIZE as u64;
        if gpa < scratch_end && gpa + len as u64 > SCRATCH_GPA {
            gpa = scratch_end;
        }
        let slot = self.next_slot;
        // KVM_MEM_READONLY *is* the seal: guest reads and executes these pages,
        // but a guest write exits to us instead of landing.
        Self::set_region(self.vm()?, slot, gpa, len, map.ptr as u64, KVM_MEM_READONLY)?;
        self.next_slot += 1;
        self.next_gpa = gpa + len as u64;
        self.tools.insert(
            hash.clone(),
            Tool {
                map,
                slot,
                gpa,
                len,
            },
        );
        Ok(())
    }

    fn unmap(&mut self, hash: &Hash) -> Result<(), VmmError> {
        let tool = self
            .tools
            .remove(hash)
            .ok_or_else(|| VmmError::Backend(format!("{hash} is not mapped")))?;
        // Deleting the memslot revokes the pages from the running guest now.
        Self::set_region(self.vm()?, tool.slot, tool.gpa, 0, 0, 0)?;
        Ok(())
    }

    fn freeze_readonly(&mut self) -> Result<(), VmmError> {
        if self.ram_frozen {
            return Ok(());
        }
        let ram_addr = self.ram()?.ptr as u64;
        let vm = self.vm()?;
        // KVM cannot change flags on a live slot: delete, re-add read-only.
        Self::set_region(vm, RAM_SLOT, 0, 0, 0, 0)?;
        Self::set_region(vm, RAM_SLOT, 0, RAM_SIZE, ram_addr, KVM_MEM_READONLY)?;
        self.ram_frozen = true;
        Ok(())
    }
}

/// Hand-assembled 16-bit real-mode guest programs for the proof harness.
/// Layout assumptions: flat segments (base 0), code at [`ENTRY`], observations
/// written to [`SCRATCH`].
pub mod guest {
    /// `mov byte [addr], val`
    fn poke(addr: u16, val: u8) -> [u8; 5] {
        [0xc6, 0x06, addr as u8, (addr >> 8) as u8, val]
    }

    /// Write `val` at `addr`, then halt.
    pub fn prog_poke(addr: u16, val: u8) -> Vec<u8> {
        let mut p = poke(addr, val).to_vec();
        p.push(0xf4); // hlt
        p
    }

    /// Try to write `target` (expected sealed), then mark `mark = mval` to
    /// prove execution continued past the blocked write, then halt.
    pub fn prog_poke_then_mark(target: u16, tval: u8, mark: u16, mval: u8) -> Vec<u8> {
        let mut p = poke(target, tval).to_vec();
        p.extend_from_slice(&poke(mark, mval));
        p.push(0xf4);
        p
    }

    /// Copy the byte at `src` to `dst` (`mov al, [src]; mov [dst], al`), halt.
    pub fn prog_copy_byte(src: u16, dst: u16) -> Vec<u8> {
        vec![
            0xa0,
            src as u8,
            (src >> 8) as u8, // mov al, [src]
            0xa2,
            dst as u8,
            (dst >> 8) as u8, // mov [dst], al
            0xf4,             // hlt
        ]
    }

    /// Far-jump to `target` — e.g. straight into a sealed tool page.
    pub fn prog_jmp_far(target: u16) -> Vec<u8> {
        vec![0xea, target as u8, (target >> 8) as u8, 0x00, 0x00]
    }

    /// A minimal "tool": executable bytes that write `val` at `mark` and halt.
    /// Sealed into the guest, this is the code the cell runs *out of* the
    /// read-only page — proving r-x mapping with real execution.
    pub fn tool_stub(mark: u16, val: u8) -> Vec<u8> {
        prog_poke(mark, val)
    }

    /// The hostile guest: claim C1's real adversary.
    ///
    /// A guest that is not merely privileged but **in full control of its own
    /// address translation** — it enters 32-bit protected mode, installs page
    /// tables it wrote itself, and maps the sealed tool page as *writable* in
    /// them. Guest-side, the write is entirely legal: ring 0, PTE says RW, no
    /// fault. The write still does not land, because stage-2 (EPT) sits below
    /// the guest's page tables and KVM_MEM_READONLY governs it. This is the
    /// difference between "the guest kernel enforces it" and "the hardware
    /// enforces it against the guest kernel".
    pub mod hostile {
        use super::super::{SCRATCH_GPA, SCRATCH_SIZE};

        /// GDT lives in low RAM so the 16-bit stub can `lgdt` a 16-bit address.
        pub const GDT_GPA: u16 = 0x3800;
        /// GDT pseudo-descriptor (limit16 + base32) address, also in low RAM.
        pub const GDT_DESC_GPA: u16 = 0x3820;
        /// Page directory: first page of the scratch region.
        pub const PD_GPA: u32 = SCRATCH_GPA as u32;
        /// Page table covering the first 4 MiB: second page of scratch.
        pub const PT_GPA: u32 = SCRATCH_GPA as u32 + 0x1000;
        /// 32-bit code entry: third page of scratch.
        pub const PM_CODE_GPA: u32 = SCRATCH_GPA as u32 + 0x2000;
        /// Offset within the scratch region where the 32-bit code sits.
        pub const PM_CODE_OFF: usize = 0x2000;

        const SEL_CODE: u16 = 0x08;
        const SEL_DATA: u16 = 0x10;

        /// GDT + pseudo-descriptor blob, written into RAM at [`GDT_GPA`].
        /// Returns (offset-in-RAM, bytes) pairs.
        pub fn gdt_blobs() -> [(usize, Vec<u8>); 2] {
            // null, flat code32 (type 0x9a), flat data32 (type 0x92)
            let mut gdt = vec![0u8; 8];
            gdt.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0x9a, 0xcf, 0]);
            gdt.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0x92, 0xcf, 0]);
            let limit = (gdt.len() - 1) as u16;
            let mut desc = limit.to_le_bytes().to_vec();
            desc.extend_from_slice(&(GDT_GPA as u32).to_le_bytes());
            [(GDT_GPA as usize, gdt), (GDT_DESC_GPA as usize, desc)]
        }

        /// The scratch image: guest-authored page directory + page table that
        /// identity-map the first 4 MiB **writable** (including the sealed tool
        /// page), plus the 32-bit attack code.
        pub fn scratch_image(tool_gpa: u32, mark_gpa: u32, val: u8) -> Vec<u8> {
            let mut img = vec![0u8; SCRATCH_SIZE];
            // PD[0] -> PT, present + writable
            img[0..4].copy_from_slice(&(PT_GPA | 0x3).to_le_bytes());
            // PT: identity map 0..4 MiB, every page present + WRITABLE.
            for i in 0..1024usize {
                let pte = ((i as u32) << 12) | 0x3;
                let off = 0x1000 + i * 4;
                img[off..off + 4].copy_from_slice(&pte.to_le_bytes());
            }
            let code = pm_code(tool_gpa, mark_gpa, val);
            img[PM_CODE_OFF..PM_CODE_OFF + code.len()].copy_from_slice(&code);
            img
        }

        /// 16-bit stub (placed at the normal entry point) that installs the
        /// guest's own CR3, turns on paging + protection, and far-jumps into
        /// its 32-bit code.
        pub fn entry_stub() -> Vec<u8> {
            let mut p = vec![0xfa]; // cli
            p.extend_from_slice(&[0x0f, 0x01, 0x16]); // lgdt [imm16]
            p.extend_from_slice(&GDT_DESC_GPA.to_le_bytes());
            p.extend_from_slice(&[0x66, 0xb8]); // mov eax, imm32
            p.extend_from_slice(&PD_GPA.to_le_bytes());
            p.extend_from_slice(&[0x0f, 0x22, 0xd8]); // mov cr3, eax
            p.extend_from_slice(&[0x0f, 0x20, 0xc0]); // mov eax, cr0
            p.extend_from_slice(&[0x66, 0x0d]); // or eax, imm32
            p.extend_from_slice(&0x8000_0001u32.to_le_bytes()); // PG | PE
            p.extend_from_slice(&[0x0f, 0x22, 0xc0]); // mov cr0, eax
            p.extend_from_slice(&[0x66, 0xea]); // jmp far sel:off32
            p.extend_from_slice(&PM_CODE_GPA.to_le_bytes());
            p.extend_from_slice(&SEL_CODE.to_le_bytes());
            p
        }

        /// 32-bit code: load flat data selectors, write the sealed page, then
        /// write a marker to prove it ran to completion, then halt.
        fn pm_code(tool_gpa: u32, mark_gpa: u32, val: u8) -> Vec<u8> {
            let mut p = vec![0xb8]; // mov eax, imm32
            p.extend_from_slice(&(SEL_DATA as u32).to_le_bytes());
            p.extend_from_slice(&[0x8e, 0xd8]); // mov ds, ax
            p.extend_from_slice(&[0x8e, 0xc0]); // mov es, ax
            p.extend_from_slice(&[0x8e, 0xd0]); // mov ss, ax
            p.extend_from_slice(&[0xc6, 0x05]); // mov byte [imm32], imm8
            p.extend_from_slice(&tool_gpa.to_le_bytes());
            p.push(val);
            p.extend_from_slice(&[0xc6, 0x05]);
            p.extend_from_slice(&mark_gpa.to_le_bytes());
            p.push(0x77); // "I completed" marker
            p.push(0xf4); // hlt
            p
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cell, CellError, Phase, Verb};

    fn has_kvm() -> bool {
        // Device-node presence is not enough in CI containers: `/dev/kvm` can
        // exist while cgroup/device policy denies opening it. Hardware proofs
        // are meaningful only after the real backend has opened KVM and
        // confirmed the readonly-memslot capability it needs to seal pages.
        KvmVmm::new().is_ok()
    }

    macro_rules! require_kvm {
        () => {
            if !has_kvm() {
                eprintln!("skipping: real KVM sealing is unavailable on this host");
                return;
            }
        };
    }

    fn forked(snapshot: &str) -> KvmVmm {
        let mut v = KvmVmm::new().unwrap();
        v.fork_from_snapshot(snapshot).unwrap();
        v
    }

    #[test]
    fn fork_is_cow_and_isolated() {
        require_kvm!();
        let marker = template_marker("mote:test-cow");
        let mut a = forked("mote:test-cow");
        let b = forked("mote:test-cow");

        // both forks see the template contents
        assert_eq!(a.read_ram(MARK_OFF, marker.len()).unwrap(), marker);
        assert_eq!(b.read_ram(MARK_OFF, marker.len()).unwrap(), marker);

        // a write in cell A stays in cell A
        a.write_ram(MARK_OFF, b"CLOBBERED").unwrap();
        assert_eq!(b.read_ram(MARK_OFF, marker.len()).unwrap(), marker);

        // and never reaches the template: a fresh fork still sees the marker
        let c = forked("mote:test-cow");
        assert_eq!(c.read_ram(MARK_OFF, marker.len()).unwrap(), marker);
    }

    #[test]
    fn guest_really_executes_on_the_vcpu() {
        require_kvm!();
        let mut v = forked("mote:test-exec");
        v.write_ram(ENTRY as usize, &guest::prog_poke(SCRATCH, 0x42))
            .unwrap();
        let r = v.run_guest(ENTRY).unwrap();
        assert_eq!(r.end, RunEnd::Halted);
        assert!(r.events.is_empty());
        assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), [0x42]);
    }

    #[test]
    fn sealed_tool_write_is_blocked_below_the_guest() {
        require_kvm!();
        let mut v = forked("mote:test-seal");
        let tool = guest::tool_stub(SCRATCH, 0x99);
        let h = Hash::of(&tool);
        v.map_pages_ro_exec(&h, &tool).unwrap();
        let gpa = v.tool_gpa(&h).unwrap();

        // guest: try to overwrite the sealed tool, then prove it kept running
        v.write_ram(
            ENTRY as usize,
            &guest::prog_poke_then_mark(gpa as u16, 0x41, SCRATCH, 0x55),
        )
        .unwrap();
        let r = v.run_guest(ENTRY).unwrap();

        assert_eq!(r.end, RunEnd::Halted);
        assert!(r.events.contains(&GuestEvent::SealedWriteBlocked { gpa }));
        // the write never landed — hardware, not software, said no
        assert_eq!(v.tool_bytes(&h, 0, 1).unwrap(), tool[..1]);
        // and execution continued past the blocked write
        assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), [0x55]);
    }

    #[test]
    fn guest_reads_and_executes_from_sealed_page() {
        require_kvm!();
        let mut v = forked("mote:test-rx");
        let tool = guest::tool_stub(SCRATCH, 0x99);
        let h = Hash::of(&tool);
        v.map_pages_ro_exec(&h, &tool).unwrap();
        let gpa = v.tool_gpa(&h).unwrap();

        // read: copy the tool's first byte into scratch
        v.write_ram(ENTRY as usize, &guest::prog_copy_byte(gpa as u16, SCRATCH))
            .unwrap();
        let r = v.run_guest(ENTRY).unwrap();
        assert_eq!(r.end, RunEnd::Halted);
        assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), tool[..1]);

        // execute: jump straight into the sealed page; its code runs
        v.write_ram(ENTRY as usize, &guest::prog_jmp_far(gpa as u16))
            .unwrap();
        let r = v.run_guest(ENTRY).unwrap();
        assert_eq!(r.end, RunEnd::Halted);
        assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), [0x99]);
    }

    /// Claim C1, against the adversary that actually matters: a guest running
    /// at ring 0 that installs its OWN page tables mapping the sealed tool
    /// page writable. Guest-side the write is legal; the hardware still
    /// refuses it.
    #[test]
    fn ring0_guest_with_own_page_tables_cannot_write_sealed_pages() {
        require_kvm!();
        let mut v = forked("mote:test-hostile");
        let tool = guest::tool_stub(SCRATCH, 0x99);
        let h = Hash::of(&tool);
        v.map_pages_ro_exec(&h, &tool).unwrap();
        let gpa = v.tool_gpa(&h).unwrap();

        // The guest authors its own translation: PD/PT identity-mapping the
        // first 4 MiB *writable*, including the sealed tool page.
        let mark = 0x2100u32; // in RAM, proves the code ran to the end
        v.map_scratch_rw(&guest::hostile::scratch_image(gpa as u32, mark, 0x41))
            .unwrap();
        for (off, bytes) in guest::hostile::gdt_blobs() {
            v.write_ram(off, &bytes).unwrap();
        }
        v.write_ram(ENTRY as usize, &guest::hostile::entry_stub())
            .unwrap();

        let r = v.run_guest(ENTRY).unwrap();

        // It really did get into protected mode with paging on and run to the
        // end — this is not a guest that crashed before attacking.
        assert_eq!(r.end, RunEnd::Halted, "hostile guest should run to HLT");
        assert_eq!(
            v.read_ram(mark as usize, 1).unwrap(),
            [0x77],
            "hostile guest must have completed its 32-bit code path"
        );
        // Its PTE for the tool page says WRITABLE — the guest believes it may write.
        let pte_off = 0x1000 + (gpa as usize / PAGE) * 4;
        let pte = u32::from_le_bytes(v.read_scratch(pte_off, 4).unwrap().try_into().unwrap());
        assert_eq!(pte & 0x3, 0x3, "guest PTE should be present+writable");
        // And yet: the write was refused below the guest, and the bytes stand.
        assert!(r.events.contains(&GuestEvent::SealedWriteBlocked { gpa }));
        assert_eq!(v.tool_bytes(&h, 0, tool.len()).unwrap(), tool);
    }

    /// One physical copy serves N cells: mapping the same tool hash into many
    /// cells does not duplicate the host allocation.
    #[test]
    fn one_physical_copy_serves_many_cells() {
        require_kvm!();
        let tool = guest::tool_stub(SCRATCH, 0x99);
        let h = Hash::of(&tool);
        // The address of the one host allocation backing this hash. Asserting
        // on this rather than on the registry's *size* keeps the test honest
        // under parallel execution — the registry is process-global, so any
        // other test sealing a tool would move a count.
        let addr_before = shared_tool_map(&h, &tool).unwrap().addr();

        let mut cells: Vec<KvmVmm> = (0..64)
            .map(|_| {
                let mut v = forked("mote:test-share");
                v.map_pages_ro_exec(&h, &tool).unwrap();
                v
            })
            .collect();

        // 64 cells later, the tool is still the same single host allocation
        assert_eq!(
            shared_tool_map(&h, &tool).unwrap().addr(),
            addr_before,
            "each cell must map the one physical copy, not its own"
        );
        // and every cell can actually execute it
        for v in cells.iter_mut() {
            let gpa = v.tool_gpa(&h).unwrap();
            v.write_ram(ENTRY as usize, &guest::prog_jmp_far(gpa as u16))
                .unwrap();
            assert_eq!(v.run_guest(ENTRY).unwrap().end, RunEnd::Halted);
            assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), [0x99]);
        }
    }

    #[test]
    fn unmap_revokes_from_a_running_cell() {
        require_kvm!();
        let mut v = forked("mote:test-revoke");
        let tool = guest::tool_stub(SCRATCH, 0x99);
        let h = Hash::of(&tool);
        v.map_pages_ro_exec(&h, &tool).unwrap();
        let gpa = v.tool_gpa(&h).unwrap();

        let probe = guest::prog_copy_byte(gpa as u16, SCRATCH);
        v.write_ram(ENTRY as usize, &probe).unwrap();
        let r = v.run_guest(ENTRY).unwrap();
        assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), tool[..1]);
        assert!(r.events.is_empty());

        // revoke: the same probe now sees unmapped memory, not the tool
        v.unmap(&h).unwrap();
        let r = v.run_guest(ENTRY).unwrap();
        assert_eq!(r.end, RunEnd::Halted);
        assert!(r.events.contains(&GuestEvent::UnmappedRead { gpa }));
        assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), [0x00]);
    }

    #[test]
    fn freeze_blocks_guest_writes_but_host_harvest_works() {
        require_kvm!();
        let mut v = forked("mote:test-freeze");
        let prog = guest::prog_poke(SCRATCH, 0x42);
        v.write_ram(ENTRY as usize, &prog).unwrap();
        v.freeze_readonly().unwrap();

        let r = v.run_guest(ENTRY).unwrap();
        assert_eq!(r.end, RunEnd::Halted);
        assert!(r.events.contains(&GuestEvent::SealedWriteBlocked {
            gpa: SCRATCH as u64
        }));
        // the write was refused by hardware…
        assert_eq!(v.read_ram(SCRATCH as usize, 1).unwrap(), [0x00]);
        // …while the host still reads the workspace (harvest)
        assert_eq!(v.read_ram(ENTRY as usize, prog.len()).unwrap(), prog);
    }

    #[test]
    fn cell_lifecycle_on_real_kvm() {
        require_kvm!();
        let vmm = KvmVmm::new().unwrap();
        let mut cell = Cell::seal("cell-kvm-test", vmm, "mote:test-cell").unwrap();
        assert_eq!(cell.phase(), Phase::Materialise);

        // P1: loan a tool, run it out of the sealed page
        let tool = guest::tool_stub(SCRATCH, 0x99);
        let h = Hash::of(&tool);
        cell.map_tool(&h, &tool).unwrap();
        let gpa = cell.vmm().tool_gpa(&h).unwrap();
        cell.vmm_mut()
            .write_ram(ENTRY as usize, &guest::prog_jmp_far(gpa as u16))
            .unwrap();
        let r = cell.vmm_mut().run_guest(ENTRY).unwrap();
        assert_eq!(r.end, RunEnd::Halted);
        assert_eq!(cell.vmm().read_ram(SCRATCH as usize, 1).unwrap(), [0x99]);

        // first tainted exec ratchets shut: no more tool loans
        cell.on_first_tainted_exec();
        let late = Hash::of(b"late-tool");
        match cell.map_tool(&late, b"late-tool") {
            Err(CellError::VerbDenied {
                verb: Verb::Materialise,
                phase: Phase::Work,
            }) => {}
            other => panic!("expected materialise denial, got {other:?}"),
        }

        // revocation still reaches the running cell in P2
        cell.revoke_tool(&h).unwrap();
        assert!(cell.vmm().tool_gpa(&h).is_none());

        // dissolve freezes the cell read-only: guest writes are refused
        cell.vmm_mut()
            .write_ram(ENTRY as usize, &guest::prog_poke(SCRATCH, 0x21))
            .unwrap();
        cell.dissolve().unwrap();
        assert_eq!(cell.phase(), Phase::Dissolve);
        let r = cell.vmm_mut().run_guest(ENTRY).unwrap();
        assert_eq!(r.end, RunEnd::Halted);
        assert!(r.events.contains(&GuestEvent::SealedWriteBlocked {
            gpa: SCRATCH as u64
        }));
        assert_eq!(cell.vmm().read_ram(SCRATCH as usize, 1).unwrap(), [0x99]);
    }
}
