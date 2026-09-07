# Host-enforced model grant: integration prerequisite

Tracks [Sympozium #426](https://github.com/sympozium-ai/sympozium/issues/426).
Status: implemented and hardware-tested in the direct-KVM prototype, not yet
available through the production dispatcher or Sympozium API.

## Authority

Every `JsonPostGrant` now requires an exact model alias, a positive per-request
output token ceiling and a cumulative output reservation ceiling, in addition
to its exact endpoint and host-owned credential file. No unrestricted POST
variant or default model bypass exists. The ordinary GET ABI is unchanged.

The broker validates the guest body before DNS, credential access or curl:

- Only `model`, `max_tokens`, `stream`, `messages`, `tools` and `tool_choice`
  are supported. Required fields must be present with the right JSON types.
- Model must match the grant; `max_tokens` must be a positive integer within
  both grant limits; `stream` must be false. Alternate token parameters,
  multiple completions (`n`) and unrecognised provider parameters refuse.
- Messages are text-only. Function tools/calls are narrowly structured;
  provider-managed search tools and multimodal URL inputs refuse.
- Existing 8,192-byte request, bounded response, request-count and timeout
  controls still apply. Invalid policy/requests fail closed.

For each authorized outgoing attempt, the broker reserves the requested
`max_tokens`, not the provider-reported actual usage, against the endpoint's
cumulative allowance. Reservations use checked arithmetic. Failed requests
are not refunded: a timeout does not establish that the provider did no work.
The state belongs to the live cell's host broker, not guest memory.

This is **not a currency budget or exact model-version pin**. A provider alias
can resolve to another reported model. Prompt bytes and call count are bounded,
but provider input-token accounting, pricing, fleet/tenant budgets, durable
metering and live grant withdrawal remain separate requirements. Output limits
are enforced on requests; generation semantics still depend on the provider
honouring its API contract. Each tool process inherits the cell's broker grant;
this is not per-tool network authority separation.

## Measured proof, 2026-09-07

The warm-forked reference Harness made five requests that the host refused:
model substitution, output ceiling 513 against 512, `n:2`, streaming, and a
fourth valid-shaped model request after three reservations consumed 1,536.
Guest code checked specific broker errors for each attempt. Between those
negative probes the real DeepSeek loop executed `add(37,5) → 42`, then
`multiply(42,2) → 84`, and returned `84`.

[Committed evidence](evidence/harness-model-policy-2026-09-07.json) records
eight attempts, five denials, three successful provider responses, tool hashes,
arguments/results and the exact model policy. Reproduce using
[the borrowed-tools launcher](HARNESS_BORROWED_TOOLS_PROOF.md#reproduce).

Two earlier development runs stopped after the first tool result: reflecting
provider response extensions into the next request violated the new strict
schema. The reference client now projects both assistant messages and tool
calls onto the supported request fields. The host checks were not relaxed.
Those failed runs each incurred one model request; they are not counted as
passing proofs. Temporary credential copies were removed after testing.

Offline tests cover parameter/model escalation, required fields, multimodal
and provider-tool refusal, cumulative exhaustion, integer overflow, and no
refund after failure. The normal GET hardware probe and `make ci` are regression
checks; the billable Harness proof remains explicitly opt-in.

## Required Sympozium binding

The next contract must resolve model authority on the trusted side:

1. Resolve a namespace-authorized approved runtime separately from execution
   placement. An OCI image is not a Celln closure. Freeze runtime/closure and
   selected tool identities before dispatch, along with the adapter version.
2. Resolve the Agent's selected provider/model and allowed credential reference.
   Map that to an operator-provisioned broker grant ID/revision; never accept a
   guest or AgentRun-supplied credential file path. Do not silently fall back to
   the dispatcher's ambient provider configuration.
3. Freeze the grant identity and requested limits in the versioned dispatch
   record. The Celln operator independently authorizes the workload, runtime,
   endpoint and model and intersects requested limits with host maxima.
   Restart/retry must preserve identity and must not reset an ambiguous billed
   execution into a fresh allowance. A revoked grant must refuse on resume.
4. Provision the broker only on the forked cell, never the reusable warm mote.
   Correlate grant/policy revision, runtime/tool identities and provider usage
   with execution audit. Receipt v1alpha1 must not silently gain incompatible
   fields. Version any new request/receipt contract explicitly.
5. Prove controller → authenticated router → dispatcher → in-cell loop on the
   isolated Kind deployment, including bad grant, stale retry, cancellation and
   missing-hardware cases, before enabling the Harness + Celln UI option.

The existing production closure-egress, multi-tool and container-Harness/Celln
refusals remain intact. This work does not justify removing them by themselves.
