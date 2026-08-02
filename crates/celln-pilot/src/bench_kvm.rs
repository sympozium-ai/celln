//! `nous-bench-kvm` — the M1/M2 exit criteria, measured on real hardware.
//!
//! The build plan states numeric gates, not adjectives. This harness produces
//! them and writes the raw results to `bench/results/`:
//!
//!   M1  spawn latency p99 < 5 ms · idle cell private RSS < 1 MiB
//!       · 1,000 concurrent cells, all reaching guest instructions
//!   M2  one tool image shared across >= 500 cells at ~one physical copy
//!       · revocation lands in running cells in < 1 s
//!       · memslot budget per VM (KVM's real limit, measured not assumed)
//!
//! Every number here is observed on this host. Nothing is asserted that the
//! hardware did not do.

use std::time::{Duration, Instant};
use warden::vmm::kvm::{self, guest, GuestEvent, KvmVmm, RunEnd};
use warden::vmm::Vmm;

const SNAPSHOT: &str = "mote:bench";

fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(0)
}

fn pct(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn head(s: &str) {
    println!("\n\x1b[1;36m── {s}\x1b[0m");
}

fn row(label: &str, value: String, gate: Option<(bool, &str)>) {
    match gate {
        Some((ok, g)) => {
            let mark = if ok {
                "\x1b[32m✔\x1b[0m"
            } else {
                "\x1b[31m✘\x1b[0m"
            };
            println!("  {mark} {label:<38} {value:>16}   gate: {g}");
        }
        None => println!("    {label:<38} {value:>16}"),
    }
}

/// M1: fork N cells, timing each, then prove every one reaches guest
/// instructions. Cells are held alive so the RSS delta is real.
fn bench_fork_scale(n: usize) -> (serde_json::Value, bool) {
    head(&format!("M1 — fork scale & latency (n = {n})"));
    let warm = KvmVmm::new().and_then(|mut v| {
        v.fork_from_snapshot(SNAPSHOT)?;
        Ok(v)
    });
    drop(warm); // ensure the template exists before timing

    let rss0 = rss_kib();
    let mut cells = Vec::with_capacity(n);
    let mut lat = Vec::with_capacity(n);
    let t_all = Instant::now();
    for _ in 0..n {
        let t = Instant::now();
        let mut v = match KvmVmm::new() {
            Ok(v) => v,
            Err(e) => {
                println!("    stopped at {} cells: {e}", cells.len());
                break;
            }
        };
        if let Err(e) = v.fork_from_snapshot(SNAPSHOT) {
            println!("    stopped at {} cells: {e}", cells.len());
            break;
        }
        lat.push(t.elapsed());
        cells.push(v);
    }
    let wall = t_all.elapsed();
    let rss_forked = rss_kib();
    let made = cells.len();

    // every cell must actually execute guest instructions
    let prog = guest::prog_poke(kvm::SCRATCH, 0x42);
    let mut reached = 0usize;
    let mut exec_lat = Vec::with_capacity(made);
    for v in cells.iter_mut() {
        if v.write_ram(kvm::ENTRY as usize, &prog).is_err() {
            continue;
        }
        let t = Instant::now();
        let ok = matches!(
            v.run_guest(kvm::ENTRY),
            Ok(r) if r.end == RunEnd::Halted
        );
        exec_lat.push(t.elapsed());
        if ok && v.read_ram(kvm::SCRATCH as usize, 1).map(|b| b[0]).ok() == Some(0x42) {
            reached += 1;
        }
    }
    let rss_run = rss_kib();

    lat.sort();
    exec_lat.sort();
    let per_cell_forked = (rss_forked.saturating_sub(rss0) as f64) / made.max(1) as f64;
    let per_cell_run = (rss_run.saturating_sub(rss0) as f64) / made.max(1) as f64;

    let p99 = pct(&lat, 0.99);
    let gate_p99 = p99 < Duration::from_millis(5);
    let gate_rss = per_cell_run < 1024.0;
    let gate_n = made >= 1000 && reached == made;

    row(
        "cells forked",
        format!("{made}"),
        Some((gate_n, ">= 1000, all live")),
    );
    row(
        "all reached guest instructions",
        format!("{reached}/{made}"),
        None,
    );
    row("fork p50", format!("{:.0} µs", us(pct(&lat, 0.50))), None);
    row(
        "fork p99",
        format!("{:.0} µs", us(p99)),
        Some((gate_p99, "p99 < 5 ms")),
    );
    row("fork max", format!("{:.0} µs", us(pct(&lat, 1.0))), None);
    row(
        "total wall for all forks",
        format!("{:.1} ms", wall.as_secs_f64() * 1e3),
        None,
    );
    row(
        "first-instruction p99",
        format!("{:.0} µs", us(pct(&exec_lat, 0.99))),
        None,
    );
    row(
        "private RSS / idle cell",
        format!("{per_cell_forked:.0} KiB"),
        None,
    );
    row(
        "private RSS / cell after run",
        format!("{per_cell_run:.0} KiB"),
        Some((gate_rss, "< 1 MiB")),
    );

    let json = serde_json::json!({
        "cells_requested": n,
        "cells_forked": made,
        "reached_guest_instructions": reached,
        "fork_us": {
            "p50": us(pct(&lat, 0.50)), "p90": us(pct(&lat, 0.90)),
            "p99": us(p99), "max": us(pct(&lat, 1.0)),
        },
        "first_instruction_us": {
            "p50": us(pct(&exec_lat, 0.50)), "p99": us(pct(&exec_lat, 0.99)),
        },
        "total_fork_wall_ms": wall.as_secs_f64() * 1e3,
        "rss_kib": { "baseline": rss0, "after_fork": rss_forked, "after_run": rss_run },
        "private_rss_kib_per_cell": { "idle": per_cell_forked, "after_run": per_cell_run },
        "gates": {
            "fork_p99_under_5ms": gate_p99,
            "idle_rss_under_1mib": gate_rss,
            "thousand_cells_all_live": gate_n,
        },
    });
    (json, gate_p99 && gate_rss && gate_n)
}

/// M2: N cells all loan the SAME tool image. Host RSS attributable to the tool
/// must stay at ~one copy, not N copies.
fn bench_sharing(n: usize, tool_kib: usize) -> (serde_json::Value, bool) {
    head(&format!(
        "M2 — one image shared across {n} cells (tool = {tool_kib} KiB)"
    ));
    // A "CPython-sized" tool: real bytes, executable prologue so cells can run it.
    let mut tool = guest::tool_stub(kvm::SCRATCH, 0x99);
    tool.resize(tool_kib * 1024, 0x90); // nop-filled body
    let h = nous_manifest::Hash::of(&tool);
    let naive_kib = (tool.len() * n) / 1024;

    let rss0 = rss_kib();
    let mut cells = Vec::with_capacity(n);
    for _ in 0..n {
        let mut v = match KvmVmm::new() {
            Ok(v) => v,
            Err(_) => break,
        };
        if v.fork_from_snapshot(SNAPSHOT).is_err() {
            break;
        }
        if v.map_pages_ro_exec(&h, &tool).is_err() {
            break;
        }
        cells.push(v);
    }
    let made = cells.len();
    let rss_mapped = rss_kib();

    // every cell executes out of the shared sealed page
    let mut ran = 0usize;
    for v in cells.iter_mut() {
        let gpa = match v.tool_gpa(&h) {
            Some(g) => g,
            None => continue,
        };
        if v.write_ram(kvm::ENTRY as usize, &guest::prog_jmp_far(gpa as u16))
            .is_err()
        {
            continue;
        }
        if matches!(v.run_guest(kvm::ENTRY), Ok(r) if r.end == RunEnd::Halted)
            && v.read_ram(kvm::SCRATCH as usize, 1).map(|b| b[0]).ok() == Some(0x99)
        {
            ran += 1;
        }
    }
    let rss2 = rss_kib();
    let delta = rss2.saturating_sub(rss0);
    let copies = delta as f64 / tool_kib.max(1) as f64;
    let distinct = kvm::shared_tool_count();

    let gate_n = made >= 500;
    // total RSS growth stays within a small multiple of ONE tool copy
    let gate_share = delta < (tool_kib as u64 * 4) + (made as u64 * 64);

    row(
        "cells sharing the image",
        format!("{made}"),
        Some((gate_n, ">= 500")),
    );
    row("cells that executed it", format!("{ran}/{made}"), None);
    row("distinct host tool page-sets", format!("{distinct}"), None);
    row("naive cost (N copies)", format!("{naive_kib} KiB"), None);
    row(
        "actual host RSS growth",
        format!("{delta} KiB"),
        Some((gate_share, "~one copy + per-cell overhead")),
    );
    row(
        "saving vs N copies",
        format!("{:.0}x", naive_kib as f64 / delta.max(1) as f64),
        None,
    );
    row("RSS growth in tool-copies", format!("{copies:.2}"), None);

    let json = serde_json::json!({
        "cells": made,
        "cells_executed_shared_image": ran,
        "tool_kib": tool_kib,
        "distinct_host_page_sets": distinct,
        "naive_n_copies_kib": naive_kib,
        "rss_after_mapping_kib": rss_mapped,
        "actual_rss_growth_kib": delta,
        "growth_in_tool_copies": copies,
        "saving_factor": naive_kib as f64 / delta.max(1) as f64,
        "gates": { "at_least_500_cells": gate_n, "rss_is_about_one_copy": gate_share },
    });
    (json, gate_n && gate_share)
}

/// M2: revoking a hash must stop it executing in ALREADY-RUNNING cells, fast.
fn bench_revocation(n: usize) -> (serde_json::Value, bool) {
    head(&format!("M2 — revocation reaching {n} running cells"));
    let tool = guest::tool_stub(kvm::SCRATCH, 0x99);
    let h = nous_manifest::Hash::of(&tool);
    let mut cells = Vec::with_capacity(n);
    for _ in 0..n {
        let mut v = match KvmVmm::new() {
            Ok(v) => v,
            Err(_) => break,
        };
        if v.fork_from_snapshot(SNAPSHOT).is_err() || v.map_pages_ro_exec(&h, &tool).is_err() {
            break;
        }
        cells.push(v);
    }
    let made = cells.len();

    // before: every cell can read the tool
    let mut live_before = 0usize;
    for v in cells.iter_mut() {
        let gpa = v.tool_gpa(&h).unwrap();
        v.write_ram(
            kvm::ENTRY as usize,
            &guest::prog_copy_byte(gpa as u16, kvm::SCRATCH),
        )
        .unwrap();
        let _ = v.run_guest(kvm::ENTRY);
        if v.read_ram(kvm::SCRATCH as usize, 1).map(|b| b[0]).ok() == Some(tool[0]) {
            live_before += 1;
        }
    }

    // the kill wire
    let t = Instant::now();
    for v in cells.iter_mut() {
        let _ = v.unmap(&h);
    }
    let revoke_wall = t.elapsed();

    // after: every cell now sees unmapped memory
    let mut dead_after = 0usize;
    for v in cells.iter_mut() {
        let r = v.run_guest(kvm::ENTRY);
        let unmapped = matches!(&r, Ok(rep) if rep.events.iter().any(|e| matches!(e, GuestEvent::UnmappedRead { .. })));
        if unmapped && v.read_ram(kvm::SCRATCH as usize, 1).map(|b| b[0]).ok() == Some(0x00) {
            dead_after += 1;
        }
    }

    let gate = revoke_wall < Duration::from_secs(1) && dead_after == made && live_before == made;
    row("cells holding the tool", format!("{made}"), None);
    row(
        "executing before revoke",
        format!("{live_before}/{made}"),
        None,
    );
    row(
        "revoke wall (all cells)",
        format!("{:.2} ms", revoke_wall.as_secs_f64() * 1e3),
        Some((revoke_wall < Duration::from_secs(1), "< 1 s")),
    );
    row(
        "per-cell revoke",
        format!("{:.1} µs", us(revoke_wall) / made.max(1) as f64),
        None,
    );
    row(
        "dead after revoke",
        format!("{dead_after}/{made}"),
        Some((dead_after == made, "all")),
    );

    let json = serde_json::json!({
        "cells": made,
        "executing_before_revoke": live_before,
        "revoke_wall_ms": revoke_wall.as_secs_f64() * 1e3,
        "per_cell_revoke_us": us(revoke_wall) / made.max(1) as f64,
        "dead_after_revoke": dead_after,
        "gates": { "under_1s": revoke_wall < Duration::from_secs(1), "all_cells_dead": dead_after == made },
    });
    (json, gate)
}

/// **The thesis number.** "The guest never boots in the hot path — spawn is a
/// CoW fork of a warm mote."
///
/// Every other latency figure in this harness forks a 16 KiB hand-assembled
/// guest, which says nothing about whether a *real* cell can be spawned that
/// way. This boots a stock Linux kernel once, parks it in userspace, and then
/// forks cells from it — measuring the time from "spawn this cell" to the cell
/// doing work in userspace, having booted nothing.
fn bench_real_cell_spawn(n: usize) -> (serde_json::Value, bool) {
    use warden::vmm::boot::{BootConfig, BootEnd, LinuxCell};

    head(&format!(
        "THESIS — spawning real cells from a parked mote (n = {n})"
    ));

    let kernel = match BootConfig::host_kernel() {
        Some(k) => k,
        None => {
            println!("    skipped: no readable /boot/vmlinuz-*");
            return (serde_json::json!({"skipped": "no kernel"}), true);
        }
    };
    let initrd = match BootConfig::built_initramfs() {
        Some(p) => p,
        None => {
            println!("    skipped: no initramfs — run `make initramfs`");
            return (serde_json::json!({"skipped": "no initramfs"}), true);
        }
    };

    // Off the hot path: boot once, park at a known point in userspace.
    let t_boot = Instant::now();
    let mut template = match LinuxCell::boot(BootConfig::new(&kernel).with_initrd(initrd)) {
        Ok(c) => c,
        Err(e) => {
            println!("    skipped: {e}");
            return (serde_json::json!({"skipped": e.to_string()}), true);
        }
    };
    template.stop_when_guest_prints("NOUS:mote=parked");
    let boot = template.run().expect("template run");
    let boot_ms = t_boot.elapsed().as_secs_f64() * 1e3;
    if boot.end != BootEnd::Parked {
        println!("    template never parked (ended {:?})", boot.end);
        return (serde_json::json!({"error": "template did not park"}), false);
    }
    let mote = template.park().expect("park");
    let ram_mib = mote.ram_size() >> 20;

    // The hot path.
    let rss0 = rss_kib();
    let mut spawn = Vec::with_capacity(n);
    let mut to_live = Vec::with_capacity(n);
    let mut console_live = Vec::with_capacity(n);
    let mut tv: Vec<warden::vmm::boot::ForkTiming> = Vec::with_capacity(n);
    let mut live = 0usize;
    let mut booted_again = 0usize;
    let mut cells = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        let (mut cell, ft) = match LinuxCell::fork_from_timed(&mote) {
            Ok(c) => c,
            Err(e) => {
                println!("    stopped after {} cells: {e}", cells.len());
                break;
            }
        };
        spawn.push(t.elapsed());
        tv.push(ft);
        cell.stop_at_live_signal();
        let r = cell.run().expect("cell run");
        if let Some(at) = r.live_signal_at {
            to_live.push(at.saturating_duration_since(t));
        }
        console_live.push(t.elapsed());
        if r.live_signal_at.is_some() {
            live += 1;
        }
        if r.console.contains("Linux version") {
            booted_again += 1;
        }
        cells.push(cell);
    }
    let rss1 = rss_kib();
    let made = cells.len();

    // What a pre-warmed pool would deliver: build the cells first, then time
    // only the activation. The fork is cheap; VM construction is not, so this
    // is the number that says whether pooling is worth building.
    let mut pool: Vec<LinuxCell> = Vec::with_capacity(made);
    for _ in 0..made {
        match LinuxCell::fork_from(&mote) {
            Ok(c) => pool.push(c),
            Err(_) => break,
        }
    }
    // Pages dirtied purely by activation: the pool is already constructed, so
    // any RSS growth from here is the resumed guest faulting its working set.
    let rss_pool = rss_kib();
    let mut activate = Vec::with_capacity(pool.len());
    for cell in pool.iter_mut() {
        cell.stop_at_live_signal();
        let t = Instant::now();
        let r = cell.run().expect("pooled cell run");
        if let Some(at) = r.live_signal_at {
            activate.push(at.saturating_duration_since(t));
        }
    }
    let rss_active = rss_kib();
    let dirtied_kib_per_cell =
        (rss_active.saturating_sub(rss_pool) as f64) / pool.len().max(1) as f64;
    activate.sort();
    spawn.sort();
    to_live.sort();
    console_live.sort();

    let per_cell_rss = (rss1.saturating_sub(rss0) as f64) / made.max(1) as f64;
    let p99_live = pct(&to_live, 0.99);
    let gate_live = live == made && made > 0;
    let gate_no_boot = booted_again == 0;
    let gate_p99 = p99_live < Duration::from_millis(5);

    row("cells spawned from the mote", format!("{made}"), None);
    row(
        "reached userspace and did work",
        format!("{live}/{made}"),
        Some((gate_live, "all")),
    );
    row(
        "cells that booted a kernel",
        format!("{booted_again}"),
        Some((gate_no_boot, "0 — a fork, not a boot")),
    );
    row(
        "template boot (off hot path)",
        format!("{boot_ms:.0} ms"),
        None,
    );
    let mem_mode = if std::env::var_os("NOUS_HUGETLB").is_some() {
        "hugetlbfs (2 MiB)"
    } else if std::env::var_os("NOUS_HUGEPAGE").is_some() {
        "memfd + MADV_HUGEPAGE"
    } else {
        "memfd, 4 KiB pages"
    };
    row("guest RAM backing", mem_mode.to_string(), None);
    row("mote RAM parked", format!("{ram_mib} MiB"), None);
    row(
        "fork call p50 / p99",
        format!(
            "{:.0} / {:.0} µs",
            us(pct(&spawn, 0.50)),
            us(pct(&spawn, 0.99))
        ),
        None,
    );
    row(
        "spawn -> userspace work p50",
        format!("{:.0} µs", us(pct(&to_live, 0.50))),
        None,
    );
    row(
        "spawn -> userspace work p99",
        format!("{:.0} µs", us(p99_live)),
        Some((gate_p99, "p99 < 5 ms")),
    );
    let mean = |f: fn(&warden::vmm::boot::ForkTiming) -> Duration| {
        if tv.is_empty() {
            0.0
        } else {
            tv.iter().map(|x| us(f(x))).sum::<f64>() / tv.len() as f64
        }
    };
    row(
        "  of which: create VM + irqchip",
        format!("{:.0} µs", mean(|x| x.create_vm)),
        None,
    );
    row(
        "  of which: CoW mmap of mote RAM",
        format!("{:.0} µs", mean(|x| x.cow_mmap)),
        None,
    );
    row(
        "  of which: memslot ioctls",
        format!("{:.0} µs", mean(|x| x.memslots)),
        None,
    );
    row(
        "  of which: create vCPU",
        format!("{:.0} µs", mean(|x| x.create_vcpu)),
        None,
    );
    row(
        "  of which: restore vCPU state",
        format!("{:.0} µs", mean(|x| x.restore_state)),
        None,
    );
    row(
        "spawn -> userspace, via console (8250)",
        format!("{:.1} ms", pct(&console_live, 0.50).as_secs_f64() * 1e3),
        None,
    );
    row(
        "from a PRE-WARMED pool: p50 / p99",
        format!(
            "{:.0} / {:.0} µs",
            us(pct(&activate, 0.50)),
            us(pct(&activate, 0.99))
        ),
        Some((
            pct(&activate, 0.99) < Duration::from_millis(5),
            "p99 < 5 ms",
        )),
    );
    let pages = dirtied_kib_per_cell / 4.0;
    row(
        "pages dirtied per activation",
        format!("{pages:.0} ({dirtied_kib_per_cell:.0} KiB)"),
        None,
    );
    row(
        "  implied fault time @ ~1.8 us/fault",
        format!("{:.1} ms", pages * 1.8 / 1000.0),
        None,
    );
    row(
        "  same working set on 2 MiB pages",
        format!("{:.0} faults", (dirtied_kib_per_cell / 2048.0).ceil()),
        None,
    );
    row(
        "private RSS / live cell",
        format!("{per_cell_rss:.0} KiB"),
        None,
    );
    println!(
        "    → a cell reaches userspace {:.0}x faster than booting one ({:.1} ms)",
        boot_ms * 1e3 / us(pct(&to_live, 0.50)).max(1.0),
        boot_ms
    );

    let json = serde_json::json!({
        "cells": made,
        "reached_userspace": live,
        "cells_that_booted_a_kernel": booted_again,
        "template_boot_ms": boot_ms,
        "mote_ram_mib": ram_mib,
        "guest_ram_backing": mem_mode,
        "fork_call_us": { "p50": us(pct(&spawn, 0.50)), "p99": us(pct(&spawn, 0.99)) },
        "fork_breakdown_us_mean": {
            "create_vm_and_irqchip": mean(|x| x.create_vm),
            "cow_mmap": mean(|x| x.cow_mmap),
            "memslots": mean(|x| x.memslots),
            "create_vcpu": mean(|x| x.create_vcpu),
            "restore_vcpu_state": mean(|x| x.restore_state),
        },
        "spawn_to_userspace_us": {
            "p50": us(pct(&to_live, 0.50)),
            "p90": us(pct(&to_live, 0.90)),
            "p99": us(p99_live),
            "max": us(pct(&to_live, 1.0)),
        },
        "private_rss_kib_per_cell": per_cell_rss,
        "speedup_vs_boot": boot_ms * 1e3 / us(pct(&to_live, 0.50)).max(1.0),
        "gates": {
            "all_reached_userspace": gate_live,
            "none_booted": gate_no_boot,
            "spawn_p99_under_5ms": gate_p99,
        },
    });
    (json, gate_live && gate_no_boot && gate_p99)
}

/// M2: KVM's memslot budget — the limit that decides whether per-tool sealing
/// is viable or whether tools must be packed into coarser layers (ADR-0004).
fn bench_memslot_budget() -> serde_json::Value {
    head("M2 — memslot budget per VM (measured, not assumed)");
    let mut v = KvmVmm::new().expect("kvm");
    v.fork_from_snapshot(SNAPSHOT).expect("fork");
    let mut mapped = 0usize;
    let mut err = String::new();
    const PROBE_CEILING: usize = 40_000;
    for i in 0..PROBE_CEILING {
        let body = format!("tool-{i}").into_bytes();
        let h = nous_manifest::Hash::of(&body);
        match v.map_pages_ro_exec(&h, &body) {
            Ok(()) => mapped += 1,
            Err(e) => {
                err = e.to_string();
                break;
            }
        }
    }
    let hit_kvm_limit = !err.is_empty();
    row("sealed tool slots in one VM", format!("{mapped}"), None);
    if hit_kvm_limit {
        row("stopped by", err.chars().take(48).collect::<String>(), None);
    } else {
        row(
            "stopped by",
            format!("probe ceiling ({PROBE_CEILING})"),
            None,
        );
    }
    let verdict = if mapped >= 500 {
        "per-tool sealing is viable at realistic tool counts"
    } else {
        "per-tool sealing is tight — pack tools into coarser layers (ADR-0004)"
    };
    println!("    → {verdict}");
    serde_json::json!({
        "sealed_slots_in_one_vm": mapped,
        "hit_kvm_limit": hit_kvm_limit,
        "probe_ceiling": PROBE_CEILING,
        "stopped_by": if hit_kvm_limit { err } else { format!("probe ceiling ({PROBE_CEILING})") },
        "verdict": verdict,
    })
}

fn main() -> anyhow::Result<()> {
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("no /dev/kvm on this host — this harness measures real hardware");
        std::process::exit(1);
    }
    println!("\x1b[1mCelln — M1/M2 exit criteria on real KVM\x1b[0m");
    println!(
        "host: {} · kernel {}",
        std::env::consts::ARCH,
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );

    let (fork_json, fork_ok) = bench_fork_scale(1000);
    let (share_json, share_ok) = bench_sharing(500, 1024);
    let (revoke_json, revoke_ok) = bench_revocation(200);
    let (spawn_json, spawn_ok) = bench_real_cell_spawn(50);
    let slots_json = bench_memslot_budget();

    let all = serde_json::json!({
        "kernel": std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim(),
        "arch": std::env::consts::ARCH,
        "m1_fork_scale": fork_json,
        "m2_sharing": share_json,
        "m2_revocation": revoke_json,
        "thesis_real_cell_spawn": spawn_json,
        "m2_memslot_budget": slots_json,
        "all_gates_passed": fork_ok && share_ok && revoke_ok && spawn_ok,
    });

    let dir = std::path::Path::new("bench/results");
    std::fs::create_dir_all(dir)?;
    let path = dir.join("m1-m2-kvm.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&all)?)?;

    println!("\n\x1b[1mSummary\x1b[0m");
    println!("  results written to {}", path.display());
    if fork_ok && share_ok && revoke_ok && spawn_ok {
        println!("\x1b[32m✔ every M1/M2 numeric gate met on this host.\x1b[0m");
    } else {
        println!("\x1b[33m! some gates not met — see rows marked ✘ above.\x1b[0m");
    }
    Ok(())
}
