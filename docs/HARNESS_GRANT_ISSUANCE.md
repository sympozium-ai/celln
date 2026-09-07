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

## Expiring profiles for unattended provisioning

`celln.dev/model-issuer-profile-v2` keeps the fields above and **requires** an
`expiry` object. Obtain this host's clock with `celln harness-profile-clock`:
the versioned report contains `bootId`, `boottimeMs`, and `maxLifetimeMs` (300000).
It reads no credentials and grants no authority. The operator may copy the boot
identity and observed time into this additional profile field:

```json
{
  "bootId": "<this host's reported Linux boot UUID>",
  "issuedAtBoottimeMs": 1234000,
  "expiresAtBoottimeMs": 1354000
}
```

These are elapsed boot milliseconds, **not Unix timestamps**. The numbers above
are illustrative; use the actual host report and an independently approved
lifetime of at most five minutes. Linux `CLOCK_BOOTTIME` includes suspend time
and does not follow wall-clock adjustments. The boot UUID must match; profiles
from a previous boot refuse. Other operating systems return `Unsupported`.
This trusts the host kernel/clock and operator configuration, not tenant time.

Future issuance times, expired profiles (including equality at the deadline),
zero/reversed/overlong windows and missing expiry refuse. V1 cannot carry expiry;
v2 cannot omit it. Earlier Celln versions reject v2 rather than ignore expiry.
Every issuance policy check and v3 grant resolution enforces this window,
including the serving path's recheck after warm preparation. The profile may
remain on disk after a reconciler crashes, but its authority at a new check does
not remain valid indefinitely. Profile removal can still withdraw it earlier.

Expiry is an **admission gate**, not live cancellation: an execution already
admitted remains bounded by its existing execution deadline and budgets. It
does not prove active-cell or fleet-wide withdrawal. There is no lease renewal;
editing the expiry changes the pinned profile hash and invalidates old grants.
New authority requires independent reapproval and issuance, with the same
execution ownership/replay rules; expiry never authorizes replay. Unattended
Sympozium provisioning must require v2 and startup reconciliation before claiming
this protection. Legacy v1 profiles retain explicit-operator compatibility and
do not gain expiry automatically.

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
