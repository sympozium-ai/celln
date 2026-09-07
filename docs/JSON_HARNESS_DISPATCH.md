# Native JSON Harness: host-authorized dispatch

Progresses [Sympozium epic #426](https://github.com/sympozium-ai/sympozium/issues/426).
The [native JSON adapter](JSON_TOOL_HARNESS.md) now has an explicitly versioned
request, operator grant and authenticated HTTP dispatcher proof. This does not
yet connect it to Sympozium runtime/catalogue selection or the lending UI.

## Request and immutable authority

`celln.dev/v1alpha3` requires `harness.contractVersion: celln.json-tools/v1`.
v1alpha1 has no Harness; v1alpha2 retains the two-integer reference contract.
Cross-version/contract substitutions refuse. Receipt v1alpha3 uses the existing
receipt shape; consumers must explicitly support the version, not downgrade it.

The enclosing request identifies one admitted mote and one primary runtime with
its signed precomposed closure. Only agent lane, required hardware isolation,
one HTTPS origin, no workspace/inputs/forge and no user invocation arguments are
supported. The closure contains exactly the runtime, `/pilot-fetch` and the
0–16 selected static tools; extra members and interpreter closures refuse.
Dynamic dependency composition remains a separate implementation gate.

The Harness binding includes `modelGrant.hash`, `model`, bounded `task`,
`borrowedTools` and `json: {system, maxTurns, maxCalls}`. The persona is at most
2048 bytes, turns 1–6 and calls 0–16. Each tool retains its unique name/path,
executable hash and description, and requires `jsonStdio`:

| Field | Meaning |
|---|---|
| `abi` | Exactly `celln.json-stdio/v1`; never interpreted as argv |
| `inputSchema`, `outputSchema` | Exact BLAKE3 hashes of bounded schema bytes |
| `inputBytes`, `outputBytes` | Explicit 1–65536-byte ceilings |
| `timeoutMs` | Explicit 1–30000-ms child deadline |

Schema data lives in the host content-addressed `STATE/tool-schemas` store.
The host reads each object with the schema byte ceiling, verifies its hash and
compiles the exact schema through the same bounded parser as the guest. Inputs
must be object schemas. Missing, tampered, oversized or unsupported schemas
refuse before warm preparation/model I/O. No request supplies a host file path.
Public store membership is not approval: the operator grant must independently
authorize every selected executable, schema identity and limit.

`STATE/trusted-harness/<grant-hash-hex>.json` remains operator-owned, not a
user-uploadable artifact store. JSON grants require:

- `apiVersion: celln.dev/harness-grant-v2` and
  `contractVersion: celln.json-tools/v1`.
- Exact `caller`, `mote`, `runtime`, `closure`, `model`, ordered `borrowedTools`
  (including ABI/schema/limit fields), and `json` persona/loop options.
- `url`: the sole requested HTTPS origin plus `/chat/completions`.
- Absolute host-only `credentialFile`, `maxRequests` (1–6), `maxOutputTokens`
  (512), and `maxTotalOutputTokens` (512–3072).

The request's exact JSON turn ceiling must fit both `maxRequests` and the total
512-token-per-request reservation budget. This prevents a configured loop from
being knowingly underfunded; it is not currency billing or a provider-success
promise. A v1 grant cannot authorize JSON execution. Only task data varies
without a new exact grant; catalogue-driven grant issuance/intersection remains
to be implemented. No request can self-issue a grant by uploading its bytes.

The host constructs and validates the guest configuration (64 KiB ceiling),
including the initial model envelope (8 KiB ceiling). Later conversation growth
can still exhaust the envelope; the loop fails closed and does not retry tool
side effects. Static maxima are ceilings, not a promise every maximum-size
selection fits simultaneously.

The grant/schema resolution is repeated after warm preparation. Credentials and
model authority attach only to the forked cell. The existing synced local
attempt tombstone forbids automatic replay with fresh allowance, including after
restart. Local grant removal refuses new launches; live/fleet withdrawal and
distributed metering/recovery are not implemented by this contract.

## Actual proof and reproduction

The [real DeepSeek dispatch record](evidence/json-harness-dispatch-2026-09-07.json)
captures authenticated loopback HTTP → dispatcher → warm-forked KVM cell →
schema-bound `uppercase({"text":"celln"})` → `length({"text":"CELLN"})` →
`CELLN has length 5`. It asserts two executable/schema identities, three broker
requests, a matching v1alpha3 receipt, correlated audit, and caller/tool/grant,
local replay and grant-withdrawal refusals. Audit records dissolution. This is
not the router/Kind/Sympozium path. The temporary credential copy was removed;
no cluster deployment or production configuration changed.

The same guest binary also passed the [seven-case scripted KVM regression](evidence/json-harness-dispatch-scripted-2026-09-07.json),
including invalid selection/arguments/results, child deadline/output overflow
and final-turn refusal. That suite is explicitly not an AI test.

Portable tests separately cover persona/schema/limit grant mismatches,
underfunded model budgets, schema absence/tampering/limits, legacy-contract
confusion and initial-envelope overflow. Runtime tool-call events are transcript
evidence, not individually hardware-attested per-tool receipts. The receipt
identifies the runtime; the request and audit correlate the selected closure and
grant. No general HarnessSession, MCP or arbitrary OCI compatibility is implied.

Build the static binaries as in the adapter guide, then package without model
calls or KVM execution:

```sh
CELLN_PILOT_DIR="$PWD/target/validation/x86_64-unknown-linux-musl/release" \
CARGO_TARGET_DIR=target/validation cargo run -p celln-pilot --features kvm \
  --bin celln-json-harness-proof -- --package-only
```

Use the printed package directory and a private authorized host credential:

```sh
CELLN_HARNESS_PACKAGE=/absolute/printed/package \
CELLN_MODEL_TOKEN_FILE=/absolute/private/provider-token \
CARGO_TARGET_DIR=target/validation cargo test -p celln-cli --bin celln \
  dispatch_http::harness_tests::json_harness_model_over_authenticated_dispatch \
  -- --ignored --exact --nocapture
```

This explicitly billable test requires real KVM and a readable kernel; explicit
execution fails rather than claiming success when hardware is unavailable. Its state/grants are
temporary; the [example request](../examples/execution/harness-json.json) records
the proof identities, not installed authority on another host.

The test also accepts an explicit `CELLN_HARNESS_CONTROLLER_HOOK` supporting
the JSON contract. The paired Sympozium implementation at
[`2dd256c`](https://github.com/sympozium-ai/sympozium/commit/2dd256cd20bf7cd822d5f108b493fc56febb4758)
provides `test/integration/test-celln-harness-controller.sh`. Set
`CELLN_CONTROLLER_KUBECONFIG` to the isolated test kubeconfig. For
`kind-celln-deployed`, also set `CELLN_PAUSE_TEST_CONTROLLER=1`; the hook refuses
unfinished runs or an unexpected controller, temporarily pauses that named test
deployment, and restores it with UID/replica checks. Never use production config.

On 2026-09-07 the [actual controller proof](https://github.com/sympozium-ai/sympozium/blob/2dd256cd20bf7cd822d5f108b493fc56febb4758/docs/evidence/celln-json-harness-controller-2026-09-07.json)
passed with three additional real DeepSeek requests (six including direct
dispatch): Kubernetes AgentRun → actual host controller → authenticated host
dispatcher → JSON Harness in a warm-forked cell → uppercase/length → final
answer. Sympozium persisted the exact binding and matching receipt/audit;
zero Jobs and zero live cells were observed. Test namespace and temporary
credential copy were removed and the test controller restored to 1/1 available.
This is not deployed router or catalogue-selection proof. The linked record
labels working-tree provenance and the tested controller binary exactly.

## Remaining product gates

Extend Sympozium's catalogue/runtime ABI and trusted authority resolver, connect
approved selection and bounded grant issuance, compose/distribute exact runtime
and tool closures, verify functional admission and serving-process prewarm, and
expose permissions/refusals/results in the UI. Then repeat real-model and
adversarial proofs through the deployed user journey and implement external
conversation state/lifecycle. Capability discovery remains preflight-only with
artifact readiness `not_checked`, not a positive readiness claim for any named
runtime/tool selection. The epic remains open.
