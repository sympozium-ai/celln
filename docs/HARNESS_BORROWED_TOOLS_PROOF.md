# In-cell reference Harness with lent executable tools

Measured 2026-09-07. Tracks [Sympozium #426](https://github.com/sympozium-ai/sympozium/issues/426).
This is a prototype prerequisite, not completion of the product epic.

## Actual result

The native Rust reference Harness ran in the agent lane of a real KVM cell,
spawned by CoW fork of a parked warm mote. The Harness made three model POSTs
through the host broker; the provider reported `deepseek-v4-flash` for the
requested `deepseek-chat` alias. The model requested:

1. The separately compiled `/add` executable with `37,5`, returning `42`.
2. The independently hashed `/multiply` executable with `42,2`, returning `84`.
3. After receiving both tool results, a final answer of `84`.

Guest code checked the lent executable hashes, attempted writable opens (denied),
and actually attempted to execute `/unselected` (EACCES). That executable was
physically present in the sealed filesystem, but excluded from the admitted
closure member graph and strict Landlock grants. These are guest attempts, not
host-only assertions. The existing hardware sealing suites cover stage-2 write
protection; this particular writable-open probe alone does not prove stage-2.

[Committed evidence](evidence/harness-borrowed-tools-2026-09-07.json) includes
individual binary identities, closure image identity, test publisher, provider
response IDs, usage, tool arguments/results and host counters: three requests,
zero rejected requests, 1,708 response bytes. Total reported model usage was
1,534 tokens. `make ci` passed after the implementation.

## Reproduce

Requires `/dev/kvm`, a readable supported host kernel, ext2/initramfs tooling,
the Rust musl target and an authorized DeepSeek credential in a private host
file. This opt-in test makes billable model requests; ordinary CI does not.

```sh
cargo build --release --target x86_64-unknown-linux-musl -p celln-pilot \
  --bin celln-pilot --bin pilot-fetch --bin celln-harness-reference
export CELLN_PILOT_DIR="$PWD/target/x86_64-unknown-linux-musl/release"
export CELLN_MODEL_TOKEN_FILE=/absolute/path/to/private-provider-token
cargo run -p celln-pilot --features kvm --bin celln-harness-proof
```

For an external Cargo target directory, point `CELLN_PILOT_DIR` there instead.
The launcher prints its evidence directory, retaining console, events, signed
closure and image files for inspection. It never copies the credential into
the guest image. Remove your temporary credential copy after testing.

## Scope and remaining work

- This is a narrow reference Harness, not Pi, Hermes or compatibility with an
  arbitrary OCI AgentRuntime. It invokes binaries directly, not MCP.
- Tools are separate executable artifacts supplied by the proof launcher, not
  built-in Harness functions. User upload, catalogue admission, policy approval
  and composition UX are not implemented by this test.
- The launcher creates an ephemeral test publisher and trusts it explicitly.
  This exercises signature verification, not independent operator admission.
- All descendants share the cell's narrowed authority, including its model
  broker permission. This does not prove per-tool authority separation or live
  revocation. Console events are not independently attested per-tool receipts.
- This is direct host KVM execution, not the deployed Sympozium controller →
  router → daemon path. Production multi-tool and closure-egress refusal guards
  are unchanged. The prototype POST grant still needs host-enforced model and
  parameter budgets before product exposure.
- The next integration must bind approved runtime identity, execution placement,
  explicit tool identities and broker grants in a versioned Sympozium contract,
  then prove that exact path before exposing the Harness + Celln opt-in.

The complete acceptance requirements remain in
[HARNESS_EXECUTION_REQUIREMENTS.md](HARNESS_EXECUTION_REQUIREMENTS.md).
