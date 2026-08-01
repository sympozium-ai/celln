//! `nous-boot-kvm` — boot a stock Linux kernel in a Nouscell microVM.
//!
//! M1/M2 proved the enforcement layer against hand-assembled guests. This
//! carries a real, unmodified distro kernel on the same substrate: the 64-bit
//! Linux boot protocol, a serial console, and an attested tool page-set sealed
//! into the guest's physical address space while it boots.
//!
//! What this does NOT yet prove is the **VFS↔memslot join** — that a guest
//! `mmap(PROT_EXEC)` of a tool lands on the sealed memslot rather than a
//! page-cache copy. That needs a guest-side consumer and is the next milestone.

use nous_manifest::Hash;
use warden::vmm::boot::{BootConfig, BootEnd, LinuxCell};

fn main() -> anyhow::Result<()> {
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("no /dev/kvm on this host");
        std::process::exit(1);
    }
    let kernel = match std::env::args().nth(1) {
        Some(p) => p.into(),
        None => match BootConfig::host_kernel() {
            Some(k) => k,
            None => {
                eprintln!("no readable /boot/vmlinuz-* found; pass a bzImage path");
                std::process::exit(1);
            }
        },
    };

    println!("\x1b[1mNouscell — stock Linux kernel on the microVM substrate\x1b[0m");
    println!("kernel: {}", kernel.display());

    let mut cfg = BootConfig::new(&kernel);
    match BootConfig::built_initramfs() {
        Some(initrd) => {
            println!(
                "initrd: {} (guest init from guest/init/init.c)",
                initrd.display()
            );
            cfg = cfg.with_initrd(initrd);
        }
        None => println!("initrd: none — run `make initramfs` to reach guest userspace"),
    }
    println!("memory: {} MiB", cfg.mem_size >> 20);
    println!("cmdline: {}\n", cfg.cmdline);

    let mut cell = LinuxCell::boot(cfg)?;

    // Seal an attested tool into the running guest's physical address space,
    // above RAM and outside the e820 map, exactly as a cell would.
    let tool = b"#!/nous/attested\nthis is lent tool code the guest may never write\n".to_vec();
    let h = Hash::of(&tool);
    let gpa = cell.seal_tool(&h, &tool)?;
    println!("sealed tool {h} at GPA {gpa:#x} (read-only memslot, outside e820)\n");

    let r = cell.run()?;

    println!("\x1b[1;36m── first 20 console lines\x1b[0m");
    println!("{}", r.head(20));
    println!("\n\x1b[1;36m── last 20 console lines\x1b[0m");
    println!("{}", r.tail(20));

    println!("\n\x1b[1mResult\x1b[0m");
    println!(
        "  console output   {} bytes over {} vCPU exits",
        r.console.len(),
        r.exits
    );
    println!("  wall clock       {:?}", r.elapsed);
    println!("  ended            {:?}", r.end);
    println!("  reached kernel   {}", r.reached_kernel());
    println!("  reached handoff  {}", r.reached_userspace_handoff());
    println!("  guest init ran   {}", r.guest_init_ran());
    if r.guest_init_ran() {
        for key in ["mmap_anon", "tool_open"] {
            println!(
                "    guest reports {key:<10} {}",
                r.guest_report(key).unwrap_or("-")
            );
        }
    }

    let after = cell
        .tool_bytes(&h, tool.len())
        .ok_or_else(|| anyhow::anyhow!("tool vanished"))?;
    let intact = after == tool;
    println!("  sealed bytes intact after a full kernel boot: {intact}");
    anyhow::ensure!(intact, "a kernel boot altered sealed tool bytes");

    if r.reached_kernel() && r.end != BootEnd::TimedOut {
        println!("\n\x1b[32m✔ a stock distro kernel booted on the Nouscell substrate.\x1b[0m");
        println!("  next: the VFS↔memslot join — make a guest mmap of /tools/<x> land on");
        println!("  the sealed memslot rather than a page-cache copy (docs/findings/m2.md).");
    } else {
        println!("\n\x1b[33m! boot did not complete — see console above.\x1b[0m");
    }
    Ok(())
}
