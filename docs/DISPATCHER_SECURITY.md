# Dispatcher security boundary

`celln dispatcher` speaks authenticated **plaintext HTTP**. It does not
implement native TLS. The bearer token protects requests only when the
transport also protects that token from observation.

The dispatcher therefore binds to `127.0.0.1:8787` by default and refuses any
non-loopback `--listen` address. For a fleet deployment, put a TLS-terminating
reverse proxy or an equivalently authenticated encrypted transport in front of
the dispatcher. Only after that boundary exists may the operator add
`--unsafe-non-loopback`; the flag merely permits the bind and prints a warning.
It does not enable TLS.

For example, with a same-host TLS reverse proxy forwarding to loopback, no
unsafe flag is needed:

```console
celln dispatcher \
  --listen 127.0.0.1:8787 \
  --token-file /etc/celln/dispatcher-token/token
```

## Credential rotation

The credential file must contain at least 24 printable ASCII non-whitespace
bytes, with at most 4096 file bytes; surrounding whitespace is trimmed. Startup
validates the file, and every protected request reopens it. Rotate with atomic
file replacement or a projected Kubernetes Secret directory, not a `subPath`
mount. Old credentials return 401 once the replacement is visible. Invalid or
unreadable files return 503 without falling back to a cached credential; fixing
the file restores authentication without a restart. Credential contents are
never included in these errors. Already authorized requests may finish.

`GET /v1/health` remains public and does not certify authentication readiness.
Verify rotation using a protected endpoint. Router and dispatcher Secret
projections update independently: expect temporary authentication failures until
both see the same backend token. This is single-token rotation, not a zero-downtime
overlapping-key protocol. Do not replay an execution under a new ID to bypass an
authentication failure; retain its original owner and request identity.

## Host-owned egress policy

An execution request cannot grant itself network authority. The dispatcher
starts with a deny-all egress policy. The operator may add exact DNS hostnames
with repeatable `--allow-egress-host` flags or the comma-separated
`CELLN_DISPATCHER_EGRESS_HOSTS` environment variable:

```console
celln dispatcher \
  --token-file /etc/celln/dispatcher-token/token \
  --allow-egress-host api.example.com \
  --allow-egress-host objects.example.com
```

Each `capabilities.egress` value in an otherwise valid request must be an HTTPS
destination whose exact hostname appears in that host-owned allowlist. The
dispatcher returns HTTP 403 for an out-of-policy destination before registering
the execution or invoking a model provider. Wildcards, schemes, ports, paths,
and URL fragments are not valid allowlist entries. This admission policy is in
addition to the warden fetch broker's per-request bounds, HTTPS-only checks,
DNS pinning, public-address check, and redirect reauthorization.
