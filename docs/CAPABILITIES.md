# Authenticated execution-plane capabilities

`GET /v1/capabilities` is a read-only, separately versioned preflight endpoint
on both dispatcher and router. It neither creates a cell nor claims an execution
owner. A reachable TCP port, HTTP 200, or a positive eligible-node count is not
proof that a particular Harness/task can execute.

## Authentication and deployment

The dispatcher requires its backend bearer credential. The router accepts its
existing execution-client credential, or an optional **distinct read-only**
credential configured with `--capability-token-file PATH`. This latter token is
accepted only for the two read-only discovery aggregates, `GET /v1/capabilities`
and `GET /v1/cells` (below): it cannot submit, poll, audit or cancel executions,
read `/v1/node`, or reach any `/v1/parents` route. Do not give the UI/API server the execution-client or backend token
just to discover readiness.

All configured credentials reload per request, use bounded validation, and must
be pairwise distinct. Missing/invalid configured credentials return 503; wrong
or absent caller credentials return 401. If no capability token is configured,
only the existing execution-client credential can read router capabilities.
This optional flag preserves existing router startup commands. Use projected
Secret directories, not `subPath` mounts, and retain authenticated/encrypted
transport. This endpoint does not add TLS to Celln.

Sympozium still needs coordinated API-server credential mounting, narrowly
scoped NetworkPolicy ingress, and a version-aware consumer before this replaces
its TCP-only check. That integration is not delivered merely by adding this
endpoint. Never relax ingress to all namespace Pods for capability discovery.

## Wire contract

Both envelopes use `apiVersion: celln.dev/capabilities-v1alpha1` and
`preflightOnly: true`. Dispatcher fields:

- `binaryVersion`: build package version, not an image digest or attestation.
- `node`: the existing NodeEligibility fields (snake_case), measured using the
  dispatcher's configured stores, host preflight and current reservations.
- `requestVersions`: `celln.dev/v1alpha1` and `celln.dev/v1alpha2`. Support is
  subject to their existing combination/authority guards; not every valid
  request is supported.
- `harnessContracts`: only `celln.reference-functions/v1`. This is the bounded
  reference adapter, not arbitrary OCI/Pi/Hermes Harness support.
- `persistentSessions: false`.
- `artifactReadiness: not_checked`. Readable stores are not proof of approved
  artifacts, signatures, publisher admission, model grants or a warm template.

Router fields:

- `eligibleNodes`: count of compatible authenticated reports whose node passes
  the existing eligibility predicate, including available cell/memory capacity.
- `nodes`: one entry per configured backend, with its configuration `index`,
  `preflightEligible`, and parsed `report`. A failed probe instead includes a
  generic reason; backend errors, credentials and URLs are not echoed.
- `artifactReadiness: not_checked`.

Older dispatcher 404s, auth failures, malformed or incompatible reports never
become eligible through fallback to public health/TCP. Per-node features are
not unioned: one node supporting a feature and another having capacity does not
establish an eligible placement for that feature. Zero eligible nodes can still
return HTTP 200: consumers must validate the version and report, not the status
code alone. The report does not reserve capacity; execution rechecks authority
and eligibility.

## Bounds and remaining qualification

One capability fanout runs at a time per router; concurrent probes receive 503.
Fanout is capped at 32 configured backends (larger configurations return 503
for discovery without changing execution routing). Responses are capped at
64 KiB per backend and two seconds of response reading, including slow-drip
traffic. Existing connection/DNS handling applies: a three-second connect
timeout does not bound the system resolver. No fleet-scale or latency claim is
made. Consumers need their own end-to-end deadline and must handle busy probes.

TCP tests cover read-only scope, rotation, distinct credentials, authenticated
fanout and incompatible/unavailable/capacity reports. Dispatcher tests check
version/authentication and no execution side effects. These are protocol tests,
not guest isolation or a deployed discovery proof. Named-artifact validation,
prewarming, catalogue selection and the Sympozium consumer remain follow-on work
within epic sympozium-ai/sympozium#426.

## Cells listing: `GET /v1/cells`

`celln ps` over HTTP, for operator dashboards. Read-only, versioned
`apiVersion: celln.cells/v1`, on both dispatcher and router. It replaces running
`celln ps -a --json` inside each node and publishing the output elsewhere.

Query (strict; unknown, repeated or out-of-range parameters return 400):

- `all=true|false` — include finished cells, like `ps -a`. Default `false`
  (live cells only).
- `limit=N` — newest cells returned, `1..=500`, default `100`. The registry
  keeps only the newest 500 records.

Authentication: the dispatcher requires its backend bearer credential, exactly
like `/v1/node`; parent (principal-scoped) credentials are never accepted,
because the listing spans every principal's parents. The router accepts the
execution-client credential or the read-only `--capability-token-file`
credential, and calls backends with its backend credential.

Dispatcher response:

```json
{
  "apiVersion": "celln.cells/v1",
  "node": "node-a",
  "cells": [
    {"id": "3f9c1a2b7d44", "description": "…", "status": "running",
     "backend": "kvm", "started_ms": 0, "finished_ms": null,
     "duration_ms": null, "error": null, "tools": ["/bin/ls"]}
  ],
  "parents": [
    {"incarnation": "blake3:…", "status": "ContextLost",
     "statusIsLiveOwnerObservation": false, "updated_ms": 0,
     "turns": [
       {"turnId": "t1", "stage": "parent-committed", "child": "blake3:…",
        "succeeded": true, "timeout_ms": 30000, "reserved_ms": 0}
     ],
     "turns_total": 1}
  ]
}
```

- `node`: the configured node name, as in NodeEligibility.
- `cells[].status`: `running | dissolved | refused | failed | died`, the label
  `celln ps` displays (`died`: recorded running, owning process gone). Newest
  first. `error` is truncated to 1024 bytes. Spec paths and pids are omitted.
- `parents`: the newest 50 incarnations by journal directory mtime
  (`updated_ms`), plus every owner in the live registry that still holds or may
  hold resources, however old. `status` uses the labels of
  `GET /v1/parents/<id>` (`Initializing`, `Ready`, `TurnActive`, `ContextLost`,
  `Stopping`, `Stopped`, `TeardownUncertain`). When only the journal knows an
  incarnation it is `ContextLost` with `statusIsLiveOwnerObservation: false`.
  `updated_ms` is `null` only for a live owner whose journal is unreadable.
- `turns`: the newest 32 per parent, newest first by reservation time
  (`reserved_ms`); `turns_total` counts all reservations. `stage` is
  `reserved | child-destroyed | parent-committed`. `succeeded` is present only
  from `child-destroyed` onwards. As everywhere, no stage authorizes replay.

**Privacy.** The listing carries identifiers, stages, timings and outcomes only.
Task text, messages, answers and owner principals are never included; they stay
in the journal behind the principal-scoped parent routes. Malformed, unreadable
or mid-publication journal entries are skipped, not reported.

The listing reads the cell registry and the parent journal and takes one brief
status snapshot of the live registry. It does not take the execution registry
lock and creates no state.

Router response — one entry per configured backend, by configuration `index`:

```json
{
  "apiVersion": "celln.cells/v1",
  "nodes": [
    {"index": 0, "report": {"apiVersion": "celln.cells/v1", "node": "node-a", "cells": [], "parents": []}},
    {"index": 1, "reason": "unreachable_unauthorized_or_incompatible"}
  ]
}
```

The router validates the query and forwards its canonical form to every backend
in parallel with the capability fan-out's bounds: at most 32 backends (more
returns 503), one cells aggregate in flight per router (concurrent requests
receive 503; independent of the capability probe), a three-second connect
timeout and two seconds of response reading. The per-backend response cap is
2 MiB rather than 64 KiB. A backend that is unreachable, unauthorized, too old
(404) or returns another `apiVersion` yields a generic `reason`; backend errors,
credentials and URLs are not echoed. No ownership ledger is read or written.
HTTP 200 with only `reason` entries is possible: consumers must inspect `nodes`.
