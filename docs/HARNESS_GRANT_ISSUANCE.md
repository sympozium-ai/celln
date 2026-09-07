# Request-bound host Harness grants

`celln harness-grant REQUEST --profile NAME` is a local operator command, not
an authenticated tenant upload API. It issues a JSON Harness grant only when
the operator has independently provisioned
`ROOT/trusted-model-profiles/NAME.json` approving the exact request binding.
The profile directory, grant directory and credential mapping must be writable
only by trusted operators. Artifact-store access must not grant access to them.

`celln harness-binding REQUEST` prints the binding for review, granting no
authority. It parses a bounded declared request and hashes its normalized JSON
with only `harness.modelGrant.hash` replaced by the BLAKE3 hash of empty bytes.
Thus task, persona, caller, execution ID, time/resource limits and all selected
artifact/schema identities are covered without a circular grant hash. This is
a versioned serialization contract, not the hash of the original HTTP bytes.

The independently reviewed host profile has this shape:

```json
{
  "apiVersion": "celln.dev/model-issuer-profile-v1",
  "requestBinding": "blake3:<reviewed binding>",
  "credentialFile": "/operator-owned/provider-token",
  "model": "deepseek-chat",
  "url": "https://api.deepseek.com/chat/completions",
  "maxRequests": 3,
  "maxOutputTokens": 512,
  "maxTotalOutputTokens": 1536
}
```

Do not create this profile merely because an untrusted request asks for it.
The operator must approve the complete request, including identity, behavior
and spending authority, through an independent trust path. The issuer does not
read credential contents or call a provider. It accepts profile names containing
1–64 ASCII letters/digits/underscores/hyphens, not arbitrary input paths.

Issuance runs challenge-bound member verification in a sealed cell without
executing the Harness/tools, resolves the admitted closure and schemas, and
validates the full existing JSON broker contract. In particular, each configured
turn requires a reserved 512 output tokens. It rechecks the profile before
atomically publishing a private, content-addressed `harness-grant-v3` file with
no overwrite. Repeating the identical issuance accepts only identical existing
bytes. The output includes a request with the issued grant hash, but no host
credential path or contents.

V3 binds the exact profile revision and normalized request. Every grant
resolution rereads the profile; deletion, any byte change or request substitution
refuses. This prevents an old grant file bypassing profile withdrawal at a new
resolution. It is not a fleet-wide active-cell withdrawal claim. Existing
manually provisioned v1/v2 grants keep their prior compatibility contract and
do not acquire this new guarantee.

## Scope and proof

This process's member-check cache is not the serving dispatcher's cache.
Issuance does not advertise readiness, prove functional adapter conformance,
distribute artifacts, execute the Harness, or implement Sympozium's authenticated
policy-to-host provisioning bridge. Those gates remain required.

Portable tests cover exact request binding, self-hash normalization, path
refusal, profile revision/withdrawal, issuer downgrade refusal and no publication
when hardware/artifacts are unavailable. The explicit ignored
`json_harness_grant_issuance_on_real_kvm` test uses `CELLN_HARNESS_PACKAGE` from
the native JSON proof package, calls issuance twice, checks idempotent bytes,
resolves the issued v3 grant, and removes the profile to prove refusal. It uses
a nonexistent credential path and makes no model calls. Require its explicit
`PASS real-KVM issuer` output; portable tests alone are not a hardware proof.

The [2026-09-07 recorded run](evidence/harness-grant-issuer-2026-09-07.json)
passed that explicit hardware test, along with portable `make ci` and
all-target/all-feature Clippy. It proves local issuance and resolution only.
