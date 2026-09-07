//! A bounded cache of prepared, authority-free motes. Preparation may boot;
//! every execution, including the first, forks the parked template.

use std::sync::{Arc, Mutex, OnceLock};
use warden::vmm::boot::{BootConfig, BootEnd, LinuxCell, Mote};

// One retained template bounds idle RAM to one configured guest. In-flight
// forks keep their own references. This is separate from active guest-RAM
// reservations; it is not included in a process-RSS guarantee.
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
pub(super) fn evict() {
    *CACHE.get_or_init(|| Mutex::new(None)).lock().unwrap() = None;
    warden::vmm::kvm::collect_unused_tools();
}
#[cfg(test)]
pub(super) static PREPARATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static PROOF_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn fork(
    key: String,
    tools: Vec<String>,
    prepare: impl FnOnce() -> Result<(BootConfig, Vec<u8>), String>,
) -> Result<LinuxCell, String> {
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
    LinuxCell::fork_from(&mote).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
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
