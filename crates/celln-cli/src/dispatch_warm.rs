//! A bounded cache of prepared, authority-free motes. Preparation may boot;
//! every execution, including the first, forks the parked template.

use std::sync::{Arc, Mutex, OnceLock};
use warden::vmm::boot::{BootConfig, BootEnd, LinuxCell, Mote};

// One retained template bounds idle RAM to one configured guest. In-flight
// forks keep their own references; aggregate node accounting belongs to #5.
type Cached = Option<(String, Arc<Mote>)>;
static CACHE: OnceLock<Mutex<Cached>> = OnceLock::new();
#[cfg(test)]
pub(super) static PREPARATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(super) static PROOF_LOCK: Mutex<()> = Mutex::new(());

pub(super) fn fork(
    key: String,
    prepare: impl FnOnce() -> Result<(BootConfig, Vec<u8>), String>,
) -> Result<LinuxCell, String> {
    let mote = {
        let mut cache = CACHE
            .get_or_init(|| Mutex::new(None))
            .lock()
            .map_err(|_| "warm mote cache poisoned".to_owned())?;
        if let Some((_, mote)) = cache.as_ref().filter(|(k, _)| k == &key) {
            Arc::clone(mote)
        } else {
            let (cfg, payload) = prepare()?;
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
            *cache = Some((key, Arc::clone(&mote)));
            mote
        }
    };
    LinuxCell::fork_from(&mote).map_err(|e| e.to_string())
}
