# In-cell model broker — first prerequisite proof

2026-09-07: a static guest probe running in the agent lane in a real KVM cell
initiated an authenticated DeepSeek JSON POST through `pilot-fetch` and warden.
It received the model response and checked the completion inside the guest.
The API credential was read from an operator-owned host file, not delivered to
the guest or placed in curl arguments.

This is **not** the completed Agent Harness + borrowed-tools proof. It is gate
1's minimal model-call prerequisite in [the requirements](HARNESS_EXECUTION_REQUIREMENTS.md).
It uses the direct hardware proof launcher, not Sympozium, the Kind router path
or a production Harness adapter. It does not demonstrate an agent tool loop,
multiple lent tools, warm production dispatch, conversational persistence,
runtime admission or tenant budget enforcement.

## Observed result

- Guest completed the existing agent-lane checks: raw I/O devices inaccessible,
  io_uring and x32 socket bypasses denied, permitted broker ports accessible,
  widening I/O permissions denied, and adjacent port access caused SIGSEGV.
- Host broker counters: 2 requests, 1 rejection (the intentional malformed
  permission probe), 475 successful response bytes.
- Requested endpoint: `https://api.deepseek.com/chat/completions`.
- Requested model alias: `deepseek-chat`; provider reported `deepseek-v4-flash`.
  These identities are recorded separately, not treated as exact model pinning.
- Completion ID: `d9930ced-7749-40ce-8108-6da73cc59286`.
- Guest-checked completion: `CELLN_MODEL_PROOF_OK`.
- Provider-reported usage: 19 prompt tokens + 7 completion tokens = 26 tokens.

No credential or private publisher key is part of this record.

## Broker contract in this increment

Existing GET URL requests keep their wire format. A new optional JSON request
uses `apiVersion: celln.fetch/v1`, `method: POST`, `url` and an object `body`.
Unknown fields, methods and versions refuse. `pilot-fetch --json-stdin` accepts
bounded request data without putting the body in its arguments. The existing
PIO ports and 8192-byte request / 1 MiB client response limits are unchanged.

Host policy must explicitly lend a `JsonPostGrant` for the exact endpoint,
including its host-owned bearer credential file. GET host allowlists do not
imply this grant. The regular dispatcher does not yet accept or provision
model grants: only the explicitly configured hardware proof enables one.

The host checks its host allowlist/public destination and pins DNS, disables
curl configuration/proxies, verifies TLS, bounds calls/body/time, and never
follows redirects or automatically retries a POST. Credential files reload on
each call; malformed/missing values refuse. No guest headers, file references
or proxy options are accepted. Credential staging uses a temporary mode-0600
host file, removed when the request completes.

An exact endpoint grant is **not** a model/token/cost policy. Product integration
must validate selected model and permitted request parameters, add per-run
budget/usage accounting, address credential lifecycle/withdrawal and durable
audit, and define ambiguous POST failures. This increment remains experimental.

## Reproduce

Requires real KVM, a readable kernel, the static guest toolchain and a separately
provisioned mode-0600 file containing the authorized provider key. Do not put the
key in a command line. The following makes one billed request:

```sh
CELLN_MODEL_TOKEN_FILE=/operator/provisioned/deepseek-token \
  cargo run -p celln-pilot --features kvm --bin celln-fetch-proof -- \
  https://api.deepseek.com/chat/completions
```

The smoke's model is currently fixed to `deepseek-chat`, its completion budget
to 64 tokens, and its prompt to the proof marker. This is deliberate fixture
scope, not a configurable Harness API. Without `CELLN_MODEL_TOKEN_FILE`, the
same launcher exercises the original GET path:

```sh
cargo run -p celln-pilot --features kvm --bin celln-fetch-proof -- https://example.com/
```

For a checkout using an external Cargo target directory, build the musl guest
binaries first and set `CELLN_PILOT_DIR` to that target's
`x86_64-unknown-linux-musl/release` directory. Neither the existing GET command
nor normal host grants opt into provider credentials implicitly.
