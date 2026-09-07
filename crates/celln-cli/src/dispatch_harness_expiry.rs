//! Admission expiry, not renewal or active-cell revocation. Linux boot identity
//! and CLOCK_BOOTTIME avoid wall-clock rollback and invalidate prior-boot files.
use serde::{Deserialize, Serialize};

const MAX_LIFETIME_MS: u64 = 300_000;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Expiry {
    boot_id: String,
    issued_at_boottime_ms: u64,
    expires_at_boottime_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Clock {
    boot_id: String,
    boottime_ms: u64,
}

impl Expiry {
    pub(super) fn validate_current(&self) -> Result<(), String> {
        self.validate(&host_clock()?)
    }

    fn validate(&self, clock: &Clock) -> Result<(), String> {
        let lifetime = self
            .expires_at_boottime_ms
            .checked_sub(self.issued_at_boottime_ms);
        if !valid_boot_id(&self.boot_id)
            || self.boot_id != clock.boot_id
            || !matches!(lifetime, Some(1..=MAX_LIFETIME_MS))
            || self.issued_at_boottime_ms > clock.boottime_ms
            || clock.boottime_ms >= self.expires_at_boottime_ms
        {
            return Err("operator model profile expired or invalid for this host boot".into());
        }
        Ok(())
    }
}

fn valid_boot_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

#[cfg(target_os = "linux")]
fn host_clock() -> Result<Clock, String> {
    use std::io::Read;
    let mut boot_id = String::new();
    std::fs::File::open("/proc/sys/kernel/random/boot_id")
        .and_then(|f| f.take(128).read_to_string(&mut boot_id))
        .map_err(|_| "host boot identity unavailable")?;
    let boot_id = boot_id.trim().to_owned();
    if !valid_boot_id(&boot_id) {
        return Err("invalid host boot identity".into());
    }
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: points to initialized writable storage of the required type.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return Err("host boot clock unavailable".into());
    }
    let boottime_ms = (time.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add(time.tv_nsec as u64 / 1_000_000))
        .ok_or("host boot clock overflow")?;
    Ok(Clock {
        boot_id,
        boottime_ms,
    })
}

#[cfg(not(target_os = "linux"))]
fn host_clock() -> Result<Clock, String> {
    Err(
        "Unsupported: expiring model profiles require Linux boot identity and CLOCK_BOOTTIME"
            .into(),
    )
}

pub(crate) fn inspect_clock() -> anyhow::Result<u8> {
    let clock = host_clock().map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        serde_json::json!({
            "apiVersion": "celln.dev/model-profile-clock-v1",
            "bootId": clock.boot_id, "boottimeMs": clock.boottime_ms,
            "maxLifetimeMs": MAX_LIFETIME_MS, "executionAuthorized": false
        })
    );
    Ok(0)
}

#[cfg(test)]
pub(super) fn test_expiry(lifetime_ms: u64) -> Expiry {
    let clock = host_clock().unwrap();
    Expiry {
        boot_id: clock.boot_id,
        issued_at_boottime_ms: clock.boottime_ms,
        expires_at_boottime_ms: clock.boottime_ms + lifetime_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_bounded_exclusive_and_boot_specific() {
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let mut expiry = Expiry {
            boot_id: id.into(),
            issued_at_boottime_ms: 100,
            expires_at_boottime_ms: 200,
        };
        for (now, valid) in [
            (99, false),
            (100, true),
            (199, true),
            (200, false),
            (u64::MAX, false),
        ] {
            assert_eq!(
                expiry
                    .validate(&Clock {
                        boot_id: id.into(),
                        boottime_ms: now
                    })
                    .is_ok(),
                valid
            );
        }
        assert!(expiry
            .validate(&Clock {
                boot_id: "other-boot".into(),
                boottime_ms: 150
            })
            .is_err());
        for end in [0, 100, 300_101, u64::MAX] {
            expiry.expires_at_boottime_ms = end;
            assert!(expiry
                .validate(&Clock {
                    boot_id: id.into(),
                    boottime_ms: 100
                })
                .is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn reads_real_boot_clock_without_wall_time() {
        let first = host_clock().unwrap();
        let second = host_clock().unwrap();
        assert!(valid_boot_id(&first.boot_id));
        assert_eq!(first.boot_id, second.boot_id);
        assert!(second.boottime_ms >= first.boottime_ms);
    }
}
