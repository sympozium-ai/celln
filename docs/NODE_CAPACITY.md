# Dispatcher capacity and readiness

The dispatcher atomically reserves a cell slot, the request's full
`memoryBytes`, and one broker slot for any request with nonempty egress.
Reservation occurs before forging or launching, under the execution-registry
lock. Multiple destinations share one synchronous per-cell broker. The limits
are `--max-cells`, `--memory-bytes`, and `--egress-slots` (or their existing
`CELLN_*` environment variables). The default zero egress slots now means no
egress-enabled execution can be admitted, even if host destination policy
allows its hostname. Configure both policy and capacity when enabling fetch.

Memory is an aggregate active guest-RAM commitment, not process RSS or a
physical host-memory guarantee. The bounded warm cache retains one mote;
sealed tool pages, old templates referenced by active forks, artifact buffers,
forge processes and host overhead are additional. Operators must budget these
separately or use host resource controls. CoW sharing never discounts active
reservations: every guest can dirty its full private allocation.

Cancellation only signals a worker. It does not release the reservation until
that worker finishes cleanup and publishes a terminal state. Success, failure,
refusal, timeout and cancelled cleanup all release capacity. Worker creation
failure releases the pre-launch reservation too. Finished records retained for
polling do not consume capacity. Duplicate request IDs return the existing
record without reserving again.

The service takes an exclusive OS lock for its state root to prevent duplicate
dispatchers advertising the same process-local budget. The lock is released on
exit; its persistent file is not a stale-owner signal. Other live process
records lack reliable memory/broker declarations, so their usage makes available
memory and egress zero rather than inventing headroom. This is a dispatcher
budget, not coordination with arbitrary processes using another state root or
starting independently of this service. Run one managed dispatcher per node.

## Reports

For versioned discovery through the router, see
[authenticated capabilities](CAPABILITIES.md). Its preflight result deliberately
does not advertise readiness for an unchecked runtime/tool bundle.

`GET /v1/health` remains public and returns HTTP 200 for a reachable service;
`ok` describes admission preflight, not merely `/dev/kvm` pathname presence.
It uses configured mote/tool-store directories, the loader's kernel-format
check with matching modules, CPU virtualization flags and KVM read-only memslot
support. Empty readable stores are valid; this does not promise a requested
object exists. The nested `node` includes current available `memory_bytes`,
`egress_slots`, `live_cells` and `max_cells`; configured totals are separate.
Missing resources or exhausted memory/cell slots make `ok` false. Zero egress
slots do not prevent non-network requests.

`GET /v1/node` requires the dispatcher bearer token and adds warm-mote and
resolved-tool hash hints from the live cache. `warm: null` means cache state
is currently unknown/busy; `warm: []` means observed empty. Each hint includes
the template guest-memory size. Forge templates have no declared mote hash.
Hints are advisory, not new authority: execution still verifies objects and
checks current mote/input policy and tool revocation. They are not included in
the public health response.

Both responses explicitly say `preflight_only: true`. No cheap probe proves a
guest boots or satisfies a particular declared bundle; real guest conformance
and execution remain the evidence for those properties. Standalone
`celln node probe` cannot see a dispatcher's pre-cell reservations: use the
authenticated live endpoint for scheduling. When it observes legacy live cells,
it conservatively advertises zero available memory and egress.

## Verification

Unit tests race 16 admissions against aggregate memory/broker limits, cover
unknown/excess usage and every active/terminal phase, check exclusive ownership,
and exercise configured health paths and authentication over actual TCP.
The real KVM declared-substrate test checks cache hints against the exact
resolved mote/tool identities and continues to exercise warm isolation,
workspace/input denial, cancellation and timeout. `make ci` includes the host
regressions; the ignored guest proof must also be run on a KVM host.
