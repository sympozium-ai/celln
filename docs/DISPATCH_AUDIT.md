# Correlated execution audit

`GET /v1/executions/<request-id>/audit` requires the dispatcher bearer token.
It returns `apiVersion: "celln.dev/audit-v1alpha1"`, request/caller/workload/node
identities, a bounded lifecycle event list, observed execution evidence, and
the original terminal receipt when available. Unknown/expired audits return 404.
Audits share execution-record lifetime and retention; this is not durable
storage or an OpenTelemetry exporter.

## Compatibility

The existing `celln.dev/v1alpha1` request, receipt and ordinary execution polling
response are unchanged. Strict receipt readers therefore keep working. Audit
consumers opt into the separate endpoint and version, and can parse its nested
`receipt` with the existing strict receipt schema. A caller correlates the
envelope and receipt by request, node and cell IDs.

Host and pilot must both use dispatch protocol 5. Rebuild and repin older
declared bundles; protocol 3/4 cannot establish success on this host. Legacy
non-dispatch CLI behavior is unchanged. The format identifier for the static
warm bundle is unchanged, but pinning it approves the upgraded pilot protocol.

## Evidence, not requested intent

`execution.pilot` contains the hash of the opened executable, actual selected
lane, installed workspace mode and fetch-helper grant. Pilot emits this only
after the CLOEXEC error-pipe handshake acknowledges child setup/exec, before
forwarding workload output. Failed hash admission or exec setup emits no grant.
The host checks it against the resolved tool and requested upper bounds; a
missing, duplicate, reordered or inconsistent report cannot establish success.
An agent-authored tool requested in the tool lane still reports `agent`.

`execution.granted` contains the host-enforced memory, timeout, output and egress
bounds plus the acknowledged workspace mode. It is null without a valid pilot
grant. Bounds are limits, not consumed resources or measured durations.
`execution.inputs` names hashes pilot actually rehashed and staged; staging can
precede an exec refusal, so it is distinct from granted workload authority.

`execution.substrate` records hashes of the loaded kernel, loaded initrd,
sealed toolfs and per-cell invocation bytes. The loaded initrd includes the
fixed warm-dispatch marker and therefore differs from the base bundle's initrd
hash; the unchanged receipt still identifies the declared bundle. Forge runs
have actual substrate hashes but do not invent a declared mote identity.
These are loader identities, not claims that a refused tool executed.

Broker activity is counted by the host: request attempts, denied requests and
successful response bytes. It contains no URLs, headers or response bodies.
Exit code and signal are separate fields. `watchdogStopped` describes a VMM
watchdog stop, which can be cancellation or deadline; the terminal receipt and
ordered lifecycle phases distinguish the result.

Lifecycle events include acceptance, preparation/resolution, cell-running,
dissolution and terminal outcome. Cell-running is the host entering the VMM run
loop, not proof of exec; use the pilot grant for that. Dissolution is recorded
after dropping the cell handle. Events are ordered using monotonic host
observations even when cancellation arrives before the completed cell report.
Wall-clock timestamps are for correlation, not performance measurement.

## Console integrity and sensitive data

Workload stdout/stderr remains framed output data, never an audit-control frame.
For dispatcher runs pilot disables kernel console logging before execution:
a reproduced trap diagnostic had interleaved with a grant frame on the serial
console. Kernel messages remain in the guest printk buffer, and the narrowed
workload cannot re-enable console logging. An unavailable exclusive console
refuses explicitly. Malformed reports still fail closed; they are not repaired
by searching for a plausible JSON fragment.

The audit excludes task text, argv, environment, input bytes, workload output
and free-form diagnostics. It carries identifying metadata and content hashes;
operators must not put secrets into caller/workload IDs. Ordinary inputs are
not a secret provider. Missing pre-exec evidence remains null rather than being
filled from the request. Audit data trusts the approved substrate and pilot;
it is not attestation against a malicious approved kernel.

## Verification and remaining work

Host tests cover receipt compatibility over TCP, authentication, payload
exclusion, lifecycle ordering, duplicate/reordered/spoofed grants and refused
setup. Real KVM tests check actual selected lanes, loaded image hashes, broker
denial counters, and guest failure to re-enable console logging, alongside
existing warm isolation, input/workspace, cancellation and deadline probes.
Run both ignored dispatcher suites after building static pilot binaries.

This advances #10's one-node correlation requirement. OpenTelemetry transport,
durable audit storage, richer pre-admission refusal traces and fleet-revocation
events remain separate work. #12 must validate the integrated service path and
#2 must retain fresh external Sympozium evidence before the epic can close.
