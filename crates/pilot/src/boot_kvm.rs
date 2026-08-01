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

    // What we seal. With a tool filesystem built (`make toolfs`) we seal the
    // whole image and declare it persistent memory, so the guest can reach the
    // tool the way a real one would: by path, under DAX. Otherwise we seal the
    // raw probe tool, which only the /dev/mem path can reach.
    let toolfs = std::path::Path::new("target/nous-toolfs.img");
    let (payload, sealed_what) = if toolfs.exists() {
        cfg = cfg.with_pmem(std::fs::metadata(toolfs)?.len() as usize);
        (std::fs::read(toolfs)?, "ext2 tool filesystem (DAX path)")
    } else {
        println!("(no target/nous-toolfs.img — run `make toolfs` for the file-path proof)");
        (warden::vmm::boot::probe_tool(), "raw probe tool")
    };

    let mut cell = LinuxCell::boot(cfg)?;
    let h = Hash::of(&payload);
    let gpa = cell.seal_tool(&h, &payload)?;
    println!("sealed: {sealed_what}");
    println!("  {h}");
    println!(
        "  at GPA {gpa:#x}, {} KiB, read-only memslot\n",
        payload.len() / 1024
    );

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

    let g = |k: &str| r.guest_report(k).unwrap_or("-").to_string();
    let verdict = |ok: bool| {
        if ok {
            "\x1b[32m✔\x1b[0m"
        } else {
            "\x1b[31m✘\x1b[0m"
        }
    };

    println!("\n\x1b[1mThe join, by file path — `open(\"/tools/probe\")` under DAX\x1b[0m");
    let steps = [
        ("pmem device from the sealed region", "dax_pmem", "present"),
        ("filesystem mounted with dax=always", "dax_mount", "ok"),
        ("opened the tool by path", "dax_open", "ok"),
        ("mmap(PROT_READ|WRITE|EXEC)", "dax_mmap", "ok"),
        ("it is the sealed page-set", "dax_magic", "match"),
        ("executed the tool from the mapping", "dax_exec", "ok"),
    ];
    let mut dax_ok = true;
    for (label, key, want) in steps {
        let got = g(key);
        let ok = got == want;
        dax_ok &= ok;
        println!("  {} {label:<38} {got}", verdict(ok));
    }
    let dax_write_blocked = g("dax_write_landed") == "no";
    dax_ok &= dax_write_blocked && r.sealed_writes_blocked > 0;
    println!(
        "  {} write through the file mapping refused  landed={}",
        verdict(dax_write_blocked),
        g("dax_write_landed")
    );
    println!(
        "    host counted {} refused write(s) into sealed regions",
        r.sealed_writes_blocked
    );

    println!("\n\x1b[1mThe same question via /dev/mem (the earlier, direct probe)\x1b[0m");
    println!("  mapped the sealed region          {}", g("seal_probe"));
    println!("  payload at the window start       {}", g("tool_magic"));
    if g("tool_magic") == "match" {
        println!(
            "  executed code from the mapping    returned 0x{}",
            g("tool_exec_rv").trim_start_matches('0')
        );
        println!(
            "  guest write refused               landed={}",
            g("seal_write_landed")
        );
    } else {
        println!("  (sealed payload here is the filesystem image, so the raw-tool");
        println!("   probe correctly declines to execute it — see the DAX rows above)");
    }

    let after = cell
        .tool_bytes(&h, payload.len())
        .ok_or_else(|| anyhow::anyhow!("sealed payload vanished"))?;
    let intact = after == payload;
    println!("\n  sealed bytes intact after the whole run: {intact}");
    anyhow::ensure!(intact, "the run altered sealed tool bytes");

    if !r.reached_kernel() || r.end == BootEnd::TimedOut {
        println!("\n\x1b[33m! boot did not complete — see console above.\x1b[0m");
        return Ok(());
    }
    if dax_ok {
        println!("\n\x1b[32m✔ VFS↔memslot join proven end to end.\x1b[0m");
        println!("  A stock kernel booted; guest userspace opened a tool BY PATH, mapped it,");
        println!("  executed it, and could not modify it. The mapping reaches the sealed");
        println!("  memslot, not a page-cache copy — the write proves it, because a copy");
        println!("  would have absorbed it silently.");
    } else {
        println!(
            "\n\x1b[33m! the file-path join is not demonstrated here — see the rows above.\x1b[0m"
        );
    }
    Ok(())
}
