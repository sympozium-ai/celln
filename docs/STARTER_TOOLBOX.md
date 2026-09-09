# Native parent starter toolbox

Implementation status: native and combined Sympozium system acceptance passed
on 2026-09-09, including UI starter selection, file continuity, HTTPS, cancel/
continue, refresh and teardown. The system proof installs actual signed fixture
catalogue revisions and independent grants. This is **not yet a merged release
or a long-running environment handoff**. Python is deferred.

## Guest programs

Build `celln-workspace-read`, `celln-workspace-write` and `celln-https-fetch` from
`celln-pilot` for `x86_64-unknown-linux-musl`. Publish them as signed, sealed
JSON-stdio tools with `/pilot-fetch` as an admitted dependency. Publishing a
tool does not grant its effects. The native template and operator-owned model
profile are independently pinned by the parent permit.

| Selected name | JSON input | Successful JSON result |
| --- | --- | --- |
| `workspace-read` | `{"name":"notes.txt"}` | `{"revision":1,"content":"violet"}` |
| `workspace-write` | `{"name":"notes.txt","revision":0,"content":"violet"}` | `{"revision":1}` |
| `https-fetch` | `{"url":"https://example.com/"}` | `{"content":"..."}` |

Errors return `{"error":"..."}` and do not authorize automatic retries.
Workspace revisions apply to the entire workspace, not individual files. The
first write uses revision zero; subsequent writes must use the latest observed
revision. A stale write refuses without mutation.

## Host authority

The content-hash-pinned `celln.parent-model-profile/v1` supports optional
`workspace` and `fetch` objects. Omission denies the corresponding starter
effects. These are host-owned grants, **not tenant-uploadable policy**.

```json
{
  "workspace": {
    "read": true,
    "write": true,
    "maxOperations": 16,
    "maxFiles": 32,
    "maxFileBytes": 4096,
    "maxTotalBytes": 65536
  },
  "fetch": {
    "allowHosts": ["example.com"],
    "maxRequests": 4,
    "maxResponseBytes": 16384,
    "timeoutMs": 10000
  }
}
```

Workspace data is host-memory-backed logical artifact data retained by the live
parent owner. It is not a host mount, executable filesystem, checkpoint, or
process-crash-durable store. Names reject absolute paths, dot segments and
normalization aliases. Grants are bound to a reserved child, one active child
at a time; copies share the operation budget. Cancellation, lease revocation
and parent-owner loss deny further access. Revocation is not proof of teardown.

Writes acknowledged before cancellation remain written; cancellation does not
roll back external effects. The parent answer/history commit remains separate.
Data is lost on parent-owner destruction; no transparent recreation is allowed.

Workspace operations use `celln.workspace/v1` JSON over the existing bounded
PIO broker channel, with a strict `body` tagged by `operation`. Requests are
at most 8192 encoded bytes, including JSON escaping. This keeps the existing
wire ABI and gives the guest neither network sockets nor filesystem authority.

GET authority has its own exact-host allowlist, request/response/time limits,
and counter, separate from credential-bearing model POSTs. Every redirect is
reauthorized and public IPv4 DNS results are pinned. GET ignores curl startup
configuration, URL globbing and ambient proxies. It never receives the model
credential. Both budgets are bounded again by the child lifetime.

Current tests cover host protocol, quota atomicity, stale writes, cross-turn
data, parent/child binding, cancellation/revocation, and independent GET/model
budgets. These host tests do not substitute for the required hostile-guest or
real-model E2E evidence.

## Native real-model evidence — 2026-09-09

`native_parent_starter_cross_turn_live` passed with no skips in 13.28 seconds.
It ran a retained native parent cell and three disposable worker cells with
real DeepSeek requests. Actual guest tool events prove `workspace-write` stored
`violet` in `notes.txt` at revision 1, `workspace-read` returned those bytes on
the next turn, and `https-fetch` returned the Example Domain page from the
allowlisted `https://example.com/`. All three broker audits reported zero
denials. Session destruction dropped the parent/worker owners at test exit.

Local evidence: `target/starter-live-2052225-1788939482308025817/`. This includes
conversation/tool data and is not an installation artifact or replay authority.

```sh
CELLN_PARENT_MODEL_KEY_FROM_ZSHRC=/home/axjns/.zshrc CARGO_TARGET_DIR=target/validation cargo test -p celln-cli native_parent_starter_cross_turn_live -- --ignored --nocapture --test-threads=1
```

This native proof does not exercise Kubernetes/UI admission, cancellation or
refresh, and is not a substitute for the combined release acceptance suite.

## Combined system evidence

The same test with `CELLN_INTEROP_STARTER=true` and the full external-process
configuration passed in 108.77 seconds, no skips. It exported the signed starter
catalogue, let Sympozium install actual CRs and grant documents, then exercised
UI selection, cross-turn write/read, HTTPS fetch, cancel/continue and refresh.
All three parent incarnations subsequently confirmed teardown, restored zero
live cells/full logical capacity, refused replay and reported historical
context loss after dispatcher restart. Private evidence is under
`target/starter-live-2066148-1788940479379564452/`; Sympozium's
`docs/evidence/celln-starter-system-2026-09-09.md` records the complete scope.
