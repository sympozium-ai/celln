# Router boundary — M0 first increment

The router now requires two distinct credentials:

```sh
celln route --listen 127.0.0.1:8788 \
  --backends http://127.0.0.1:8787 \
  --token-file /etc/celln/dispatcher-token/token \
  --client-token-file /etc/celln/router-client-token/token
```

`--client-token-file` authenticates callers, including polling, audit and
cancellation. `--token-file` is used only for router-to-dispatcher requests.
The controller must hold the client credential, not the dispatcher credential.
Neither is a model provider credential. Provision them through the operator's
secret manager: each must contain 24 or more printable non-whitespace ASCII
bytes, with at most 4096 file bytes. A trailing newline is allowed. Restrict file
access to the service identity; never put secrets in argv, task text or logs.

Both files are reread per request. Rotate through atomic file replacement (or
a projected Secret directory, not a Kubernetes `subPath` mount). New requests
use the new values; already authorized in-flight requests may finish. An invalid,
missing or equal pair refuses startup or returns 503 after rotation. Old client
tokens return 401. Dispatchers also reread their credential per protected request.
Backend rotation must be coordinated across both services: independent Secret
projections can temporarily disagree. There is no overlapping-key guarantee; see
[Dispatcher security](DISPATCHER_SECURITY.md#credential-rotation).

This is an intentional fail-closed CLI compatibility change. Old commands with
only `--token-file` must be updated before rollout. Do not install this binary
under an old chart and expect the existing router command to start. Pin and
coordinate a tested binary/chart release; never disable authentication as an
upgrade workaround.

There is no native TLS on either router hop. Keep raw listeners/backends on
trusted local links and expose remote access only through authenticated,
TLS-terminating infrastructure. HTTPS backend URLs now refuse instead of
silently sending bearer credentials over raw TCP. Cross-node encrypted backend
transport remains M0 work; an HTTP node URL is not encryption.

Authenticated `POST /v1/executions/:id/cancel` now forwards an empty body to the
tracked dispatcher. Its status and record are returned unchanged: 202 is only
acknowledgement, not teardown. The router also forwards the correlated audit
endpoint using the execution ID rather than looking up the literal `audit`.
Router execution IDs must be nonempty ASCII alphanumeric/dash/underscore/dot
path components, excluding `.` and `..`; unaddressable IDs refuse before
submission. This includes the UID-derived IDs emitted by Sympozium.

## Proof and remaining limitations

`cargo test -p celln-cli router::tests` exercises the real TCP parser and
forwarder with a protocol fixture: missing/wrong/backend credentials at every
execution endpoint, case-insensitive header names, duplicate/framing rejection,
client and backend rotation, admission, polling, audit, cancellation and terminal
status preservation. These are not KVM or production deployment tests.

This increment does **not** solve in-memory ownership loss across router
replicas/restarts, unhealthy-backend retry duplication, unbounded execution
tracking, dispatcher registry loss, TLS deployment, or authenticated capability
reporting. Do not treat it as multi-node readiness or M0 completion. The next
ownership design must handle ambiguous submission without rerunning side effects;
simply hashing against a changing healthy-node list is insufficient.

Tracked by [Sympozium M0](https://github.com/sympozium-ai/sympozium/issues/426)
and [the router boundary issue](https://github.com/sympozium-ai/sympozium/issues/331).
