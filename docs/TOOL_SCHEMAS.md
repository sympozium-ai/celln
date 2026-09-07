# Immutable bounded tool schemas

`celln.tool-schema/v1` is the initial, deliberately restricted structured-data
validation profile for catalogue arguments and results. `celln-manifest` exposes
`ToolSchema::parse(bytes, expected_hash)` and `validate(bytes, effective_limit)`;
both are pure, with no filesystem, network or code execution.

The expected BLAKE3 hash covers exact schema bytes. Parsing does not approve a
publisher or tool: trusted catalogue approval must bind this schema hash to the
executable revision. Both arguments and results need independently bound schemas.

## Supported grammar

Every schema node requires `type`. The following keys are the **only** supported
keys, and every listed key is required. Unknown keywords (including `$ref`,
`$schema`, `enum`, `format`, `pattern`, `default`, `description` and composition)
refuse rather than silently lose validation. This is not general JSON Schema
conformance; callers must explicitly select the profile.

| Type | Required fields and limits |
| --- | --- |
| `object` | `properties` (up to 32), `required` (unique declared names), `additionalProperties: false` |
| `array` | `items` (one schema), `minItems`, `maxItems` (0–64, ordered) |
| `string` | `minLength`, `maxLength` (0–4096 Unicode scalar values, ordered) |
| `integer` | `minimum`, `maximum` (signed 64-bit integers, ordered) |
| `boolean` | No additional fields |

Property names use 1–64 ASCII letters, digits, underscores or hyphens. Missing
required properties, undeclared properties, wrong types and out-of-bound values
refuse. Integer data must use integer JSON encoding: `1.0` and `1e0` are
explicitly unsupported, even though general JSON Schema considers them integers.
Null, floating-point numbers, tuple schemas and implicit coercion are unsupported.

The schema ceiling is 32 KiB, four nested levels below the root and 128 schema
nodes. Value validation requires an explicit 1–65536 byte ceiling, supplied from
the resolved argument/result grant; it cannot raise that grant. Raw JSON parsing
also caps nesting at 16 and nodes at 4096. Duplicate keys, invalid UTF-8, trailing
documents and non-finite/out-of-range numeric encoding are rejected. The parser
rejects duplicates before a map could overwrite them.

## Offline verification

```sh
celln schema verify arguments.schema.json \
  --expected-hash blake3:<exact-schema-hash>
celln schema verify arguments.schema.json \
  --expected-hash blake3:<exact-schema-hash> \
  --value arguments.json --max-value-bytes 4096
```

Success emits `celln.dev/tool-schema-verification-v1` JSON with the schema hash,
profile, `valueValidated` flag and `scope=schema-and-data-only`. Failure is
nonzero without a success report. Reads are bounded before parsing; the command
creates no store or approval object and uses no credentials. Reports are not
signed and must not be trusted when supplied by a tenant.

This component is **not yet connected** to catalogue admission or dispatcher
invocation. In particular, it does not change the reference Harness's two
integer-string function protocol, translate JSON to argv, or claim arbitrary
tools can run. Admission still needs trusted schema/artifact retrieval, publisher
and behavior approval, ABI compatibility and distribution/prewarming. Invocation
must validate against the frozen schema and effective byte ceiling before
executing; results need validation before returning to the model. A schema is
data validation, never executable authority.

Tests cover boundaries, malformed/duplicate JSON, exact identity, unknown
keywords, closed properties, scalar/array bounds, explicit integer encoding and
real CLI exit/stdout/no-write behavior. No KVM or provider access is required.

On 2026-09-07, `CARGO_TARGET_DIR=target/deployed make ci` passed, including
format checks, all-target/all-feature Clippy with warnings denied, full workspace
build/tests and the real schema CLI integration test. No deployed cluster was
changed and no model calls were made. This evidence covers schema/data checks,
not an integrated approval or tool-invocation workflow.
