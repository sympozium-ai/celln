//! `nous-boot-kvm` — boot a stock Linux kernel in a Nouscell microVM.
//!
//! M1/M2 proved the enforcement layer against hand-assembled guests. This
//! carries a real, unmodified distro kernel on the same substrate: the 64-bit
//! Linux boot protocol, a serial console, and an attested tool page-set sealed
//! into the guest's physical address space while it boots.
//!
//! It then asks guest userspace the question the **VFS↔memslot join** turns on:
//! map the sealed region, check it really is the sealed page-set, execute out
//! of it, and try to modify it. The seal holds through that mapping.
//!
//! The probe reaches the pages via `/dev/mem` — the shortest unambiguously
//! direct mapping. What remains is the production path: getting a *file* to
//! resolve to those same pages without a page-cache copy (ADR-0005).

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
    // above RAM and outside the e820 map, exactly as a cell would. It carries a
    // magic marker and a callable function so guest userspace can prove what it
    // actually got.
    let tool = warden::vmm::boot::probe_tool();
    let h = Hash::of(&tool);
    let gpa = cell.seal_tool(&h, &tool)?;
    println!("sealed tool {h}\n  at GPA {gpa:#x} (read-only memslot, outside e820)\n");

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

    println!("\n\x1b[1mVFS↔memslot join — what guest userspace found\x1b[0m");
    let g = |k: &str| r.guest_report(k).unwrap_or("-").to_string();
    let verdict = |ok: bool| {
        if ok {
            "\x1b[32m✔\x1b[0m"
        } else {
            "\x1b[31m✘\x1b[0m"
        }
    };
    let mapped = g("seal_probe") == "mapped";
    let magic_ok = g("tool_magic") == "match";
    let exec_ok = g("tool_exec") == "ok";
    let write_blocked = g("seal_write_landed") == "no";
    println!(
        "  {} mapped the sealed region        {}",
        verdict(mapped),
        g("seal_probe")
    );
    println!(
        "  {} it is the sealed page-set       magic {}",
        verdict(magic_ok),
        g("tool_magic")
    );
    println!(
        "  {} executed code from the mapping  returned 0x{}",
        verdict(exec_ok),
        g("tool_exec_rv").trim_start_matches('0')
    );
    println!(
        "  {} guest write refused             landed={} (byte {} -> {})",
        verdict(write_blocked),
        g("seal_write_landed"),
        g("seal_byte_before").trim_start_matches('0'),
        g("seal_byte_after").trim_start_matches('0')
    );
    println!(
        "    host counted {} refused write(s) into sealed regions",
        r.sealed_writes_blocked
    );

    let after = cell
        .tool_bytes(&h, tool.len())
        .ok_or_else(|| anyhow::anyhow!("tool vanished"))?;
    let intact = after == tool;
    println!("  sealed bytes intact after a full kernel boot: {intact}");
    anyhow::ensure!(intact, "a kernel boot altered sealed tool bytes");

    if !r.reached_kernel() || r.end == BootEnd::TimedOut {
        println!("\n\x1b[33m! boot did not complete — see console above.\x1b[0m");
        return Ok(());
    }
    if mapped && magic_ok && exec_ok && write_blocked && r.sealed_writes_blocked > 0 {
        println!("\n\x1b[32m✔ a stock distro kernel booted, and guest userspace mapped the sealed");
        println!("  tool, executed out of it, and could not modify it.\x1b[0m");
        println!("  The seal survives a userspace mapping — hardware, not the guest kernel.");
        println!("  Remaining: the production path is a filesystem (DAX), not /dev/mem.");
    } else {
        println!(
            "\n\x1b[33m! the join is not demonstrated on this host — see the rows above.\x1b[0m"
        );
    }
    Ok(())
}
