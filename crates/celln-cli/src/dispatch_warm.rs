//! A bounded cache of prepared, authority-free motes. Preparation may boot;
//! every execution, including the first, forks the parked template.

use std::sync::{Arc, Mutex, OnceLock};
use warden::vmm::boot::{BootConfig, BootEnd, LinuxCell, Mote};

// The cache retains one template. Explicit pins and in-flight forks can retain
// evicted templates too; their owners must account for that memory separately.
type Cached = Option<(String, Arc<Mote>, Availability)>;

#[derive(Clone, serde::Serialize)]
pub(crate) struct Availability {
    pub mote: Option<String>,
    pub tools: Vec<String>,
    pub guest_memory_bytes: u64,
}

/// Advisory identity hints only: never bypass pinning, integrity or policy.
/// None means the cache is busy/unknown, not proof it is empty.
pub(crate) fn availability() -> Option<Vec<Availability>> {
    let cache = CACHE.get_or_init(|| Mutex::new(None)).try_lock().ok()?;
    Some(cache.iter().map(|(_, _, hint)| hint.clone()).collect())
}
static CACHE: OnceLock<Mutex<Cached>> = OnceLock::new();
#[cfg(test)]
pub(crate) fn evict() {
    *CACHE.get_or_init(|| Mutex::new(None)).lock().unwrap() = None;
    warden::vmm::kvm::collect_unused_tools();
}
#[cfg(test)]
pub(crate) static PREPARATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static PROOF_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn fork(
    key: String,
    tools: Vec<String>,
    prepare: impl FnOnce() -> Result<(BootConfig, Vec<u8>), String>,
) -> Result<LinuxCell, String> {
    pin(key, tools, prepare)?.fork()
}

/// A prepared substrate retained independently of cache eviction. It carries
/// no per-cell invocation, model credentials, or execution authorization.
/// An enduring owner must acquire this before accepting turns, account for its
/// retained memory, and recheck live admission/grants before each child fork.
pub(super) struct PinnedMote {
    mote: Arc<Mote>,
}

impl PinnedMote {
    /// Strictly fork-only: no cache lookup, preparation callback or boot path.
    pub(super) fn fork(&self) -> Result<LinuxCell, String> {
        celln_control::check().map_err(|e| e.to_string())?;
        LinuxCell::fork_from(&self.mote).map_err(|e| e.to_string())
    }
}

pub(super) fn pin(
    key: String,
    tools: Vec<String>,
    prepare: impl FnOnce() -> Result<(BootConfig, Vec<u8>), String>,
) -> Result<PinnedMote, String> {
    let mote = {
        let mutex = CACHE.get_or_init(|| Mutex::new(None));
        let mut cache = loop {
            celln_control::check().map_err(|e| e.to_string())?;
            match mutex.try_lock() {
                Ok(cache) => break cache,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err("warm mote cache poisoned".into())
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
            }
        };
        if let Some((_, mote, _)) = cache.as_ref().filter(|(k, _, _)| k == &key) {
            Arc::clone(mote)
        } else {
            let (cfg, payload) = prepare()?;
            let hint = Availability {
                mote: if key.starts_with("forge:") {
                    None
                } else {
                    key.rsplit_once(':').map(|(hash, _)| hash.to_owned())
                },
                tools,
                guest_memory_bytes: cfg.mem_size as u64,
            };
            celln_control::check().map_err(|e| e.to_string())?;
            let mut template = LinuxCell::boot(cfg).map_err(|e| e.to_string())?;
            template
                .seal_tool(&celln_manifest::Hash::of(&payload), &payload)
                .map_err(|e| e.to_string())?;
            template.stop_when_guest_prints("CELLN:mote=parked");
            let report = template.run().map_err(|e| e.to_string())?;
            if report.end != BootEnd::Parked {
                return Err("substrate did not reach the warm mote park point".into());
            }
            let mote = Arc::new(template.park().map_err(|e| e.to_string())?);
            #[cfg(test)]
            PREPARATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Drop the only shared writable RAM mapping before publishing.
            drop(template);
            *cache = Some((key, Arc::clone(&mote), hint));
            warden::vmm::kvm::collect_unused_tools();
            mote
        }
    };
    celln_control::check().map_err(|e| e.to_string())?;
    Ok(PinnedMote { mote })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_mote_forks_after_eviction_while_parent_retains_context() {
        let Some(initrd) = std::env::var_os("CELLN_PARENT_PROBE_INITRD") else {
            eprintln!("skipping: requires CELLN_PARENT_PROBE_INITRD from mkparent-probe.sh");
            return;
        };
        let Some(kernel) = BootConfig::host_kernel() else {
            return;
        };
        if !std::path::Path::new("/dev/kvm").exists() {
            return;
        }
        let _guard = PROOF_LOCK.lock().unwrap();
        let pin = pin("parent-pin-proof".into(), vec![], || {
            Ok((
                BootConfig::new(kernel).with_initrd(std::path::PathBuf::from(initrd)),
                vec![0; 4096],
            ))
        })
        .unwrap();
        let mut parent = pin.fork().unwrap();
        parent.enable_parent_mailbox().unwrap();
        parent
            .deliver_parent_message(b"remember:parent-only")
            .unwrap();
        assert_eq!(parent.run().unwrap().end, BootEnd::Parked);
        assert_eq!(
            parent.take_parent_response().unwrap().unwrap(),
            b"1:parent-only"
        );
        evict();
        // The cache is empty. These calls cannot prepare or boot a template.
        for turn in 2..=3 {
            let mut child = pin.fork().unwrap();
            child.enable_parent_mailbox().unwrap();
            child.deliver_parent_message(b"recall").unwrap();
            let report = child.run().unwrap();
            assert_eq!(report.end, BootEnd::Parked, "{}", report.tail(20));
            assert!(!report.console.contains("Linux version"));
            assert_eq!(child.take_parent_response().unwrap().unwrap(), b"1:");
            drop(child);
            parent.deliver_parent_message(b"recall").unwrap();
            assert_eq!(parent.run().unwrap().end, BootEnd::Parked);
            assert_eq!(
                parent.take_parent_response().unwrap().unwrap(),
                format!("{turn}:parent-only").as_bytes()
            );
        }
        eprintln!("pinned mote proof: cache evicted, two real child VMs dropped, parent guest state retained");
    }
    #[test]
    fn deadline_interrupts_waiting_for_another_preparation() {
        let _guard = CACHE.get_or_init(|| Mutex::new(None)).lock().unwrap();
        let worker = std::thread::spawn(|| {
            let c = celln_control::Control::new(std::time::Duration::from_millis(30)).unwrap();
            c.scope(|| fork("not-prepared".into(), vec![], || panic!("must not prepare")))
                .err()
                .unwrap()
        });
        assert!(worker.join().unwrap().contains("deadline"));
    }
}
