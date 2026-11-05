# Native JSON-tool Harness adapter

`celln-harness-json` implements the separate `celln.json-tools/v1` native
adapter contract toward [Sympozium epic #426](https://github.com/sympozium-ai/sympozium/issues/426).
Its agent loop runs inside a sealed cell and uses explicitly lent executables
with immutable, bounded input/result schemas. It is no longer restricted to
two integer-string functions or required to invoke every available tool.

**Integration status:** the dispatcher accepts this binary only through the
explicit v1alpha3 binding and independent v2 operator grant described in
[JSON Harness dispatch](JSON_HARNESS_DISPATCH.md). It is not yet selectable
through Sympozium. The existing
`celln.reference-functions/v1` contract and refusal guards are unchanged.
Do not label this as arbitrary OCI/Pi/Hermes compatibility, a finished user BYO
workflow, or conversational HarnessSession support.

## Contract and authority

Host configuration is one bounded JSON argument (at most 64 KiB) containing:

- `contract: celln.json-tools/v1`, `task`, `system`, `url`, `model`.
- `max_turns` (1–6), `max_calls` (0–16) and `tools` (0–16 entries).
- Optional `require_tool_call: true` requires at least one actual tool execution
  before reporting successful completion. It requires a nonempty selected tool
  list, at least one call and at least two model turns. The first request uses
  `tool_choice: required`; after execution the model can return a final answer.
  A provider response that skips the required call fails locally without an
  automatic retry or a fabricated successful result. Only already-lent tools
  remain callable. This does not require every selected tool or a particular tool.
  Omission/false preserves the previous optional-call behaviour and serialized
  template bytes. Enabling it changes the immutable native turn-template binding
  and therefore requires fresh corresponding host approval; it cannot be toggled
  through turn message data. Older binaries refuse the new field rather than
  silently ignoring it. Sympozium's enduring-run development integration maps
  explicit `enduring.requireToolCall` intent through matching prepared parent
  registration. The one-shot catalogue issuer is unchanged.
  Provider semantics: [DeepSeek chat completions](https://api-docs.deepseek.com/api/create-chat-completion/).
- Optional `budget_exhaustion` says what happens when the model asks for more
  tool calls than `max_calls` leaves. `end_turn` is the default, and the only
  behaviour before this field: the turn ends with `tool call budget exhausted`
  and nothing in the batch runs. `tool_error` runs the calls that still fit the
  budget, in order, and runs **none** of the rest. Each refused call gets a
  `role:tool` result with the stable content
  `{"error":"tool call budget exhausted; answer without further tools"}`, so
  every call ID is answered and the model can finish with what it has. Under
  `tool_error`, a request on which no further call could run (the call budget
  is spent) or after which no request would remain to read a result (the last
  of `max_turns`) carries `tool_choice: none`, which the Anthropic translation
  sends as a request without tools. The model-request budget does not grow: the
  loop is still at most `max_turns` requests, within the permit's
  `MAX_TURN_MODEL_REQUESTS`. If a provider still calls a tool on the last
  request, the turn ends as before (`model budget leaves no tool result turn`)
  without running it. Batch validation is unchanged: an unselected tool, a
  repeated call ID or invalid arguments anywhere in the batch, including the
  refused part, still refuse the whole batch before any side effect, and so does
  a batch of more than 16 calls, which the broker could not replay. The worker
  reports each refused call as a `{"type":"budget",...}` event, and its
  completion carries `budgetRefusedCalls`; under `end_turn` neither appears.
  Omitting the field or setting `end_turn` keeps the serialized template bytes
  and turn-template binding unchanged (pinned by tests). `tool_error` is a
  different worker configuration and needs fresh host approval. Older workers
  refuse a template that names the field rather than ignoring it. On the scoped
  path the host sets it from the operation's `profileSpec.json.budgetExhaustion`
  (`end_turn` | `tool_error`; any other value refuses with
  `AUTH_LIMIT_OUT_OF_RANGE`).
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
binding explicitly name `celln.json-stdio/v1`; the Sympozium catalogue/runtime
schema still needs that support before its integration can be enabled.

Model arguments are validated as their original bytes before parsing, so
duplicate keys, unknown fields, wrong types and excess budgets cannot disappear
through JSON normalization. The whole proposed tool-call batch is checked
before the first call executes. A requested unselected tool or repeated call ID
refuses; omission grants nothing. A final answer may use no tools. Results must
validate against the pinned output schema before returning to the model.
Tool-call batches on the last permitted model turn refuse before execution:
there must be a remaining model turn to consume the results (under
`budget_exhaustion: tool_error` that request also withholds tools). A tool-free final
answer on the last turn is allowed. This does not promise that a later provider
request succeeds or that it has enough remaining host-granted allowance.

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

Seven real warm-forked KVM cases exercise the compiled adapter: text uppercase
then length, undeclared tool, invalid arguments, invalid output, child deadline
and output overflow, plus final-turn tool-batch refusal. The latter checks the
compiled refusal path and absence of completed-tool events; the portable test
directly proves the executor callback was never invoked. Fixture tools
deliberately use a tiny text grammar; the
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

PR review then reproduced and fixed final-turn side effects before exhaustion.
The [reviewed seven-case scripted KVM record](evidence/json-harness-reviewed-scripted-2026-09-07.json)
binds the revised binary, with full `make ci` passing again. It does not relabel
the earlier real-model run as a measurement of this later binary.

## Remaining integration gates

The host grant/request is now versioned and tested through authenticated HTTP
dispatch. Extend the Sympozium catalogue invocation ABI; bind the approved
runtime plus tool/schema/policy identities through the authority resolver;
verify and compose their exact closure; distribute and prewarm in the serving
process; expose runtime/tool selections and refusals in Sympozium. Re-run real
model and adversarial tests through that deployed path. External conversational
state, general lifecycle mediation, live withdrawal and full release gates remain
open. Neither these tests nor this binary mark the epic complete.
