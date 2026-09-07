# Native JSON-tool Harness adapter

`celln-harness-json` implements the separate `celln.json-tools/v1` native
adapter contract toward [Sympozium epic #426](https://github.com/sympozium-ai/sympozium/issues/426).
Its agent loop runs inside a sealed cell and uses explicitly lent executables
with immutable, bounded input/result schemas. It is no longer restricted to
two integer-string functions or required to invoke every available tool.

**Integration status:** this binary is not yet accepted by the dispatcher
Harness binding or selectable through Sympozium. The existing
`celln.reference-functions/v1` contract and refusal guards are unchanged.
Do not label this as arbitrary OCI/Pi/Hermes compatibility, a finished user BYO
workflow, or conversational HarnessSession support.

## Contract and authority

Host configuration is one bounded JSON argument (at most 64 KiB) containing:

- `contract: celln.json-tools/v1`, `task`, `system`, `url`, `model`.
- `max_turns` (1–6), `max_calls` (0–16) and `tools` (0–16 entries).
- Each tool has `name`, canonical absolute `path`, executable BLAKE3 `hash`,
  `description`, `input_schema`, `output_schema`, `input_bytes`, `output_bytes`
  and `timeout_ms`.
- Each schema has `bytes` (the exact JSON document as a string) and its BLAKE3
  `hash`. Both must pass `celln.tool-schema/v1`; inputs must be object schemas.
- Input/output bounds are 1–65536 bytes; tool deadlines are 1–30000 ms. Task and
  system text are each bounded at 2048 bytes. The actual broker envelope still
  has an 8192-byte ceiling, including schemas and accumulated conversation.

Tool invocation is **JSON stdin → JSON stdout**, with no user arguments or
shell. This is a new adapter ABI, not a silent reinterpretation of catalogue
`celln.argv/v1`. The catalogue/runtime schema and independently authorized host
binding must explicitly support it before integration can be enabled.

Model arguments are validated as their original bytes before parsing, so
duplicate keys, unknown fields, wrong types and excess budgets cannot disappear
through JSON normalization. The whole proposed tool-call batch is checked
before the first call executes. A requested unselected tool or repeated call ID
refuses; omission grants nothing. A final answer may use no tools. Results must
validate against the pinned output schema before returning to the model.

There are no automatic tool retries. A failed result cannot undo an already
completed side effect; it stops further execution. Tool pipes are nonblocking
and drained while input is written, with bounded stdout and 4 KiB stderr.
Per-tool deadlines kill/wait for the direct child. The enclosing host cell
watchdog/dissolution remains the final bound for descendants; this is not
per-tool microVM isolation within a shared runtime cell.

The runtime clears child environments and verifies tool hashes/unwritability.
Those checks do not manufacture hardware guarantees: the operator must deliver
the runtime and exact lent executable/dependency set as a signed sealed closure.
Raw standalone execution of this binary is not Celln isolation. All model
requests use `/pilot-fetch` and the existing host-enforced provider/model/token
grant; credentials remain host-side. Schema bytes are data, never executable
authority. No runtime-generated code, ambient tool discovery, workspace, remote
MCP authority or retained conversation state is implied.

## Functional proof versus AI proof

Build the actual static guest binaries:

```sh
CARGO_TARGET_DIR=target/validation cargo build --release \
  --target x86_64-unknown-linux-musl -p celln-pilot \
  --bin celln-pilot --bin pilot-fetch --bin celln-harness-json
```

The default proof uses a clearly labelled **scripted broker**, zero model calls:

```sh
CELLN_PILOT_DIR="$PWD/target/validation/x86_64-unknown-linux-musl/release" \
CARGO_TARGET_DIR=target/validation cargo run -p celln-pilot --features kvm \
  --bin celln-json-harness-proof
```

Six real warm-forked KVM cases exercise the compiled adapter: text uppercase
then length, undeclared tool, invalid arguments, invalid output, child deadline
and output overflow. Fixture tools deliberately use a tiny text grammar; the
adapter itself uses the bounded JSON/schema parser. The signed filesystem also
contains an unselected binary excluded from the lent closure; runtime selection
refusal is tested here, not a new claim of a guest attempted-exec attack.

An explicitly billable mode substitutes the real broker and host credential:

```sh
CELLN_MODEL_TOKEN_FILE=/absolute/private/host-token \
CELLN_PILOT_DIR="$PWD/target/validation/x86_64-unknown-linux-musl/release" \
CARGO_TARGET_DIR=target/validation cargo run -p celln-pilot --features kvm \
  --bin celln-json-harness-proof -- --real-model
```

On 2026-09-07 this passed with real DeepSeek: three broker requests, two
separately hashed tools, structured results `{"text":"CELLN"}` and
`{"length":5}`, then answer `CELLN has length 5`. The temporary host credential
copy was removed. This is **direct KVM**, not yet controller/router/catalogue
dispatch. No cluster deployment was changed. Evidence records distinguish real
and scripted modes and bind the guest binary and signed closure identities.

Committed records: [scripted six-case KVM suite](evidence/json-harness-scripted-2026-09-07.json)
and [real DeepSeek JSON-tool task](evidence/json-harness-deepseek-2026-09-07.json).
Both used the same runtime binary. Full `make ci` passed on this implementation;
the original reference Harness and dispatcher contracts remain unchanged.

## Remaining integration gates

Version the host grant/request and catalogue invocation ABI; bind the approved
runtime plus tool/schema/policy identities through the authority resolver;
verify and compose their exact closure; distribute and prewarm in the serving
process; expose runtime/tool selections and refusals in Sympozium. Re-run real
model and adversarial tests through that deployed path. External conversational
state, general lifecycle mediation, live withdrawal and full release gates remain
open. Neither these tests nor this binary mark the epic complete.
