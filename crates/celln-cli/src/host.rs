//! What this machine can actually do.
//!
//! Separated out because three different commands need the same answer, and
//! because "what can I run here" should be a question with one implementation.

use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Capability {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// What to do when `ok` is false. Empty when it is fine.
    pub fix: String,
}

#[derive(Serialize)]
pub struct Host {
    pub caps: Vec<Capability>,
}

fn cap(
    name: &'static str,
    ok: bool,
    detail: impl Into<String>,
    fix: impl Into<String>,
) -> Capability {
    Capability {
        name,
        ok,
        detail: detail.into(),
        fix: if ok { String::new() } else { fix.into() },
    }
}

impl Host {
    pub fn probe() -> Self {
        let mut caps = Vec::new();

        let kvm = std::path::Path::new("/dev/kvm").exists();
        let readable = std::fs::File::open("/dev/kvm").is_ok();
        caps.push(cap(
            "kvm",
            kvm && readable,
            if !kvm {
                String::from("/dev/kvm not present")
            } else if !readable {
                String::from("/dev/kvm present but not readable by this user")
            } else {
                String::from("/dev/kvm available")
            },
            if kvm && !readable {
                "add yourself to the kvm group: sudo usermod -aG kvm $USER (then log out and in)"
            } else {
                "enable virtualization in BIOS, or use a host with nested virt"
            },
        ));

        let virt = std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.contains("vmx") || s.contains("svm"))
            .unwrap_or(false);
        caps.push(cap(
            "cpu-virt",
            virt,
            if virt {
                "vmx/svm present"
            } else {
                "no vmx/svm in /proc/cpuinfo"
            },
            "enable VT-x/AMD-V in firmware",
        ));

        let kernel = newest_kernel();
        caps.push(cap(
            "guest-kernel",
            kernel.is_some(),
            match &kernel {
                Some(k) => format!("{}", k.display()),
                None => "no readable /boot/vmlinuz-*".into(),
            },
            "install a kernel package, or pass one with --kernel",
        ));

        caps.push(cap(
            "cargo",
            which("cargo").is_some(),
            which("cargo")
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            "only needed to build from source",
        ));

        // These build the controlled guest initramfs and, for host-path tools,
        // its sealed ext2 filesystem. Check them here rather than letting a
        // launch fail halfway through either script.
        for (name, binary, package) in [
            ("guest-c-compiler", "gcc", "gcc or build-essential"),
            ("initramfs-packer", "cpio", "cpio"),
            ("toolfs-builder", "mke2fs", "e2fsprogs"),
        ] {
            let found = which(binary);
            caps.push(cap(
                name,
                found.is_some(),
                found
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| format!("{binary} not found")),
                format!("install {package}"),
            ));
        }

        // The hardware checks above say a cell can be *sealed*. They say nothing
        // about whether anything can run inside it: that needs pilot, and a host
        // with perfect virtualisation support but no musl target boots a cell
        // that does nothing at all.
        let pilot = crate::agent::pilot_source();
        caps.push(cap(
            "guest-pilot",
            pilot.is_ok(),
            match &pilot {
                Ok(from) => from.clone(),
                Err(why) => why.clone(),
            },
            "rustup target add x86_64-unknown-linux-musl",
        ));

        Host { caps }
    }

    pub fn get(&self, name: &str) -> bool {
        self.caps.iter().any(|c| c.name == name && c.ok)
    }

    /// Can this host seal real, hardware-isolated cells?
    pub fn can_seal(&self) -> bool {
        self.get("kvm") && self.get("cpu-virt")
    }
}

/// Newest `/boot/vmlinuz-*` that also has its modules installed, since the boot
/// path loads modules and vermagic is checked exactly.
pub fn newest_kernel() -> Option<std::path::PathBuf> {
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir("/boot")
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
    found
        .iter()
        .rev()
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("vmlinuz-"))
                .map(|v| std::path::Path::new("/lib/modules").join(v).is_dir())
                .unwrap_or(false)
        })
        .cloned()
        .or_else(|| found.last().cloned())
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(bin))
            .find(|p| p.is_file())
    })
}
