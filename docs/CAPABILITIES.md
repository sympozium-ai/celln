# Authenticated execution-plane capabilities

`GET /v1/capabilities` is a read-only, separately versioned preflight endpoint
on both dispatcher and router. It neither creates a cell nor claims an execution
owner. A reachable TCP port, HTTP 200, or a positive eligible-node count is not
proof that a particular Harness/task can execute.

## Authentication and deployment

The dispatcher requires its backend bearer credential. The router accepts its
existing execution-client credential, or an optional **distinct read-only**
credential configured with `--capability-token-file PATH`. This latter token is
accepted only for `GET /v1/capabilities`: it cannot submit, poll, audit or cancel
executions. Do not give the UI/API server the execution-client or backend token
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
