# Experimental reference Harness dispatch

This page retains the v1alpha2 reference contract. The separately versioned
native JSON-tool adapter uses [v1alpha3 requests and v2 grants](JSON_HARNESS_DISPATCH.md);
it does not change the reference tool ABI.

Tracks [Sympozium #426](https://github.com/sympozium-ai/sympozium/issues/426).
Measured 2026-09-07: **actual Sympozium controller → isolated Kind Kubernetes
API → authenticated host dispatcher → warm-forked cell → DeepSeek → two lent
executable tools → persisted AgentRun result/receipt** passed.

This is an advanced one-shot reference adapter, not the completed runtime/tool
catalogue UX, Pi/Hermes support, persistent HarnessSession or deployed router /
DaemonSet topology. The model loop is inside the cell, not in the controller.

## Versioned binding

`celln.dev/v1alpha1` requests and receipts retain their existing semantics.
`celln.dev/v1alpha2` requires a `harness` object containing:

- `contractVersion: celln.reference-functions/v1`: text-only reference loop,
  exactly two static executable tools accepting two i32 string arguments.
- `modelGrant.hash`: exact BLAKE3 revision of an operator-owned grant.
- `model`: the selected provider alias, checked against that grant.
- `task`: at most 2,048 bytes of data, never executable authority.
- `borrowedTools`: exactly two unique names/paths, hashes and descriptions.

The enclosing mote and single `tools` entry identify the runtime and signed
precomposed closure. The closure must contain exactly the runtime, `/pilot-fetch`
and the two declared tools. Dependencies outside this static profile refuse.
Each member is hash-checked by pilot before execution; no arbitrary uploaded
binary becomes trusted just because it is named in the request.

Only agent lane, no workspace/inputs/forge, no invocation arguments, and one
HTTPS origin are supported. Ordinary v1alpha1 closure-egress and multi-tool
refusals remain. The new path constructs the runtime's configuration from the
validated binding; callers cannot inject proof mode or arbitrary runtime args.
See [example request](../examples/execution/harness-reference.json). Its measured
artifact references must be replaced with locally provisioned/admitted ones;
the example does not install authority or include a credential.

## Independent host admission

The operator places a bounded JSON grant in
`STATE/trusted-harness/<64-hex-blake3>.json`. Hash the exact file bytes to obtain
the request's `modelGrant.hash`. This is a privileged policy directory, **not**
an uploadable artifact store. Existing independent mote, publisher/closure and
local revocation checks also apply.

Grant fields (`camelCase`, unknown fields refuse):

| Field | Binding |
|---|---|
| `apiVersion` | `celln.dev/harness-grant-v1` |
| `caller`, `mote`, `runtime`, `closure` | Exact controller caller and immutable identities |
| `borrowedTools` | Exact ordered tool definitions from the request |
| `url`, `model` | Requested HTTPS origin + `/chat/completions`, exact model alias |
| `credentialFile` | Absolute operator-owned host path, never sent to guest |
| `maxRequests` | 1–6 requests per cell |
| `maxOutputTokens` | 512 for this initial adapter |
| `maxTotalOutputTokens` | 512–3,072 reserved output tokens per cell |

The grant is verified again after warm preparation. Model authority is attached
only to the forked cell, never the reusable warm mote. Removal/replacement of
the grant refuses subsequent launches. Host credential files still reload per
request. This is not live model-grant withdrawal during a running call.

A synced, exclusive-create tombstone under `STATE/harness-attempts/` records the
caller/request-ID pair before provider authority can be used. Local restart or
registry eviction cannot replay that attempt with fresh allowance. Failures are
conservative: an ambiguous attempt needs operator reconciliation, not automatic
replay. Tombstones are retained. **This is not distributed deduplication or
tenant/currency metering**; do not advertise safe failover to a different state
root/node. Operational retention/recovery and fleet coordination remain open.

Receipt v1alpha2 has the existing receipt shape and identifies the primary
runtime; it does not pretend every selected tool was invoked. Correlated audit
records the sealed closure/member graph and `modelGrant` revision, without task
data or credential paths. Runtime-emitted tool-call events are transcript
evidence, not separately hardware-attested per-tool receipts.

## Actual proof

[Committed evidence](evidence/harness-dispatch-controller-2026-09-07.json)
contains the direct HTTP test and the actual controller run, including model
response IDs, tool calls, runtime/closure identities, frozen request, matching
terminal receipt/audit and controller executable SHA256. It records the tested
working-tree state honestly; the original base revision is not presented as
containing this implementation.

The controller run used `add(37,5) → 42`, then `multiply(42,2) → 84`, with three
model calls and final answer `84`. No Kubernetes Job was created; the audit
recorded dissolution and the node reported zero live cells afterward. The
owned namespace and temporary provider credential copy were removed. Kind
remains running; Framework was untouched.

Negative binding coverage: wrong caller, model, runtime, tool, unknown/tampered
grant, local replay and grant withdrawal refuse. Existing guest sealing/broker
escalation proofs remain separate evidence. `make ci`, Sympozium `go build ./...`
and controller/API/webhook/orchestrator tests (including race tests) passed.

## Reproduce (explicitly billable)

Build static guest binaries as in [the reference proof](HARNESS_BORROWED_TOOLS_PROOF.md).
Set `CELLN_PILOT_DIR` to that build directory, then package without model I/O:

```sh
cargo run -p celln-pilot --features kvm --bin celln-harness-proof -- --package-only
```

Use the printed directory and a private authorized host credential file:

```sh
CELLN_HARNESS_PACKAGE=/path/to/printed/package \
CELLN_MODEL_TOKEN_FILE=/private/provider-token \
cargo test -p celln-cli harness_model_over_authenticated_dispatch -- --ignored --nocapture
```

To also exercise the actual Sympozium controller, set
`CELLN_HARNESS_CONTROLLER_HOOK` to the paired Sympozium checkout's
`test/integration/test-celln-harness-controller.sh`, and
`CELLN_CONTROLLER_KUBECONFIG` to the isolated `kind-celln-m0` kubeconfig. The hook
updates CRDs only in that explicitly selected cluster, creates an owned test
namespace, runs the built controller on the host, and cleans up its namespace
and process. Evidence stays in the package directory. It makes three additional
model requests. No default kubeconfig or production context is accepted.

## Remaining main-goal work

The Sympozium advanced binding is disabled by default. Before broad exposure:
bind approved AgentRuntime and user-selected tools through an admission/catalogue
workflow; implement the selection UX; prove authenticated router/DaemonSet
execution on Kind; define fleet retry/cancellation/revocation and conversational
lifecycle; and complete adversarial/product acceptance in the epic. A narrow
two-integer-function adapter is not general-purpose Harness compatibility.
