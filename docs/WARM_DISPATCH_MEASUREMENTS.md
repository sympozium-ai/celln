# Warm dispatch evidence — 2026-09-06

Environment: Intel Core Ultra X7 358H, 16 logical CPUs; host and guest kernel
`7.1.12-200.fc44.x86_64`; 256 MiB guest RAM, 32 MiB toolfs; local KVM.
Source: warm-dispatch implementation following substrate revision `9a34b32`.

Command:

```sh
cargo test -p celln-cli on_real_kvm -- --ignored --nocapture
```

One observed run, not a percentile distribution or a performance gate:

| Execution | End-to-end time |
| --- | ---: |
| Cold preparation, fork and marker workload | 3.01050527 s |
| Warm fork, first distinct argument | 102.080082 ms |
| Warm fork, second distinct argument | 82.925468 ms |

These timings include policy/store reads, hash verification, VM setup, guest
execution, reporting and teardown. They are **not** fork-only timings and do
not establish a sub-millisecond spawn claim. The test counts exactly one
preparation across these three declared requests. Guest code proves distinct
arguments, absence of the preceding cell's scratch file, and a fault when it
tries to read the supervisor invocation port after exec. Existing outcome
proofs also pass through the prepare/fork path.

The first actual pilot resume uncovered an incomplete snapshot: restoring only
legacy FPU registers omitted extended state and IA32_XSS, causing a guest
XRSTORS fault. Snapshots now preserve the VM-sized XSAVE area and IA32_XSS;
restoration errors refuse instead of continuing best-effort. XSAVE buffers are
sized and checked according to the [KVM API](https://docs.kernel.org/virt/kvm/api.html#kvm-get-xsave2).
Hosts without XSAVE2 support return Unsupported.

Remaining work includes fleet density and aggregate cache accounting, stable
percentile benchmarks, cancellation during preparation and an end-to-end
deadline. No claim about those follows from these measurements.
