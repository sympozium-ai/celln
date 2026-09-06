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
