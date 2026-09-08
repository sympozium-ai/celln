# Host-pinned prewarm and submission

Catalogue model profiles are host-local. A controller must not provision on one
host and let automatic placement submit the resulting request to another host.
The router accepts an optional `X-Celln-Backend` header on
`POST /v1/executions`. Its value must exactly match one operator-configured
backend URL. The ordinary execution credential is required; capability-only
credentials cannot use this path. Tenant task text must never supply the header.

A new pinned execution durably claims that backend before the first POST. No
health probe, backend selection or fallback is performed. The dispatcher still
enforces artifact, KVM, grant and capacity admission. A failed first POST retains
ownership; an identical retry polls the original execution instead of replaying
the POST. A pin conflicting with recorded ownership returns 409. Unpinned legacy
submissions retain their existing behavior; adding or removing a pin cannot move
an existing execution. Poll, audit and cancel use the durable owner and reject
an explicit pin rather than implying that it can override ownership.

`POST /v1/artifacts/prewarm` also passes through the router, but **requires** an
explicit backend pin. It preserves the bounded request and response bytes and
uses the backend credential, not the caller token. Empty or over-64-KiB bodies,
duplicate/unknown backend pins and capability-only credentials refuse. The
dispatcher validates that the request cannot execute a Harness/task and performs
the actual sealed member checks and serving-process warm preparation.

Prewarm never creates an execution ownership record. An unavailable pinned host
returns 503 without trying a spare. A successful response is an observation of
that serving process, not durable readiness, a lease, executable authority or a
guarantee that the process will survive until submission. Controllers must check
the response identity and keep issuer/serving-host configuration bound to the
frozen run. The router does not establish that two configured service URLs name
the same physical host, and this header is not a cryptographic host identity.

This remains the router's existing operator-protected HTTP transport contract;
the header does not add TLS or authorize arbitrary outbound URLs. Operators must
restrict router credentials and use stable per-host backend endpoints. Backend
list changes must not silently retarget a URL to a new host holding different
policy state.

## Verification scope

The real TCP router tests use protocol fixtures, not KVM guests. They verify
exact body/response forwarding, credential separation, refusal cases, no
prewarm ownership, no spare contacts, owner preservation across a fresh router
instance and a lost acceptance response, and no replay/reroute. Actual dispatcher
prewarm has separate KVM evidence. Combining this transport with catalogue
controller dispatch and deployed selection-specific readiness remains an
integration gate in Sympozium epic #426.
