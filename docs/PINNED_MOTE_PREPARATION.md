# Pinned mote preparation (cold path)

`celln closure prepare-mote` packages a candidate mote from an exact
operator-reviewed template and a signed closure. It replaces neither admission
nor hardware conformance. It does not boot a guest, create a warm serving mote,
issue model authority, or write either host trust policy.

The command never selects the current host kernel or searches for an initramfs.
Its template pins the kernel, pilot initrd, runtime executable/entrypoint and
composition publisher. The caller must obtain the template and its expected
BLAKE3 hash from trusted operator configuration, not from a tenant request.
Matching a supplied hash proves byte identity, not who approved those bytes.

Template format (hash values shown as placeholders):

```json
{
  "apiVersion": "celln.dev/mote-template-v1",
  "kernel": "blake3:<kernel digest>",
  "initrd": "blake3:<pilot initrd digest>",
  "runtimeExecutable": "blake3:<runtime digest>",
  "runtimeEntryPoint": "/harness",
  "composerPublisher": "<64 hex characters>"
}
```

The kernel and uncompressed newc initrd must already exist in the explicit mote
store. Hash verification is bounded to 64 MiB each. Template/descriptor/image
inputs are bounded regular files; on Unix symlinks and FIFOs refuse. The image
must match the signed closure's filesystem identity. The closure is checked
against the current host publisher/revocation policy, including signed source
closures. Its entrypoint and executable must match the exact template.

```sh
celln --root /var/lib/celln closure prepare-mote \
  --template /etc/celln/templates/native-json.json \
  --template-hash blake3:<trusted-template-digest> \
  --descriptor /var/lib/celln/build/composition/signed-closure.json \
  --toolfs /var/lib/celln/build/composition/toolfs.ext2 \
  --mote-store /var/lib/celln/motes \
  --output-dir /var/lib/celln/build/new-candidate
```

The output directory must not exist. Successful preparation writes kernel,
initrd, toolfs, signed closure, exact template and mote descriptor bytes, then a
`prepared.json` report. Existing directories and files are never overwritten.
An error may leave a partial directory for inspection; it is not automatically
deleted and must not be consumed as successful preparation. Consumers must
validate the complete report and all referenced bytes; a filename is no proof.

The report always says `admitted: false`, `executionAuthorized: false`,
`hardwareConformance: not_checked`, and `readiness: not_established`.
Content addressing alone does not grant any new mote authority. Policy is
rechecked after input reads, but this is an observation, not a policy lease.

## Remaining admission/distribution workflow

### Verify members before production admission

`celln closure check-prepared --candidate <directory> --template-hash <trusted-hash>
--mote-store <store> --tool-store <store>` regenerates the candidate from verified
inputs, then checks signed members with actual guest code in a sealed cell.
The explicit template hash must still come from trusted operator configuration.
The runtime executable must exist by hash in the tool store.

The check uses an owned temporary verification root with a copy of the current
closure policy and local manifest constraints. Only that temporary root gets a
single-candidate allowlist; production mote policy is never changed. The request
has no arguments, inputs, workspace or egress and requires hardware isolation.
Current production policy and manifest are checked again after the guest exits.
Unavailable hardware or an unsupported pilot refuses, never certifies success.

The report binds the template, candidate and signed closure to a fresh sealed
member challenge. It still says `admitted: false`: member integrity is not full
runtime functional conformance, model authorization, capacity or serving-host
readiness. Do not accept a user-supplied copy of this report as an admission token.

The explicit real-KVM signed-closure regression exercises this path before
creating any production mote allowlist, asserts guest verification and teardown,
then runs the existing hostile-guest mutation and revocation tests.

### Administrator-assisted MLP admission

On the intended serving host, an administrator can now explicitly approve the
exact reviewed candidate with:

```sh
celln --root /var/lib/celln closure admit-prepared \
  --candidate /var/lib/celln/build/new-candidate \
  --template-hash blake3:<trusted-template-digest> \
  --approve-mote blake3:<reviewed-candidate-mote-digest> \
  --mote-store /var/lib/celln/motes --tool-store /var/lib/celln/tools
```

This is an authority-changing operator command, not a tenant endpoint. Run it
under the host service account with exclusive custody of the policy/store;
new files are private to that account. The administrator is responsible for
runtime/tool functional review in addition to the mandatory member check.
Do not derive trusted template approval from a tenant's uploaded report.

Admission repeats preparation and real-KVM checking. It durably publishes the
kernel/initrd/filesystem/descriptor objects, verifies even deduplicated objects,
records check evidence, then atomically replaces the exact-mote allowlist.
Cooperating admission/withdrawal commands use a nonblocking Linux file lock;
other tools must not edit this policy concurrently. Observed external edits
refuse. All existing allowlist entries are preserved. Corrupt stored objects
refuse rather than being overwritten. No model grant or execution is issued.

Failure before the allowlist commit may leave unused immutable blobs/evidence,
but does not authorize a new mote. A lost success acknowledgement may occur
after the commit: inspect current host policy or repeat the exact command. A
retry rechecks policy and hardware; it never submits execution. Evidence alone
is not current admission. Storage must provide local Linux lock, atomic rename
and fsync semantics; shared/distributed filesystems are not qualified here.

To prevent new use of one exact mote:

```sh
celln --root /var/lib/celln closure withdraw-mote --mote blake3:<mote-digest>
```

Withdrawal atomically removes only that entry and retains artifacts/evidence.
It is repeatable, but **does not cancel active cells**. Withdraw relevant model
and tool approvals and cancel active AgentRuns separately; wait for terminal
teardown. Do not call this fleet-wide live revocation.

Register the admitted mote/closure pair with the Sympozium catalogue controller
only after installation on its explicitly pinned serving host. The controller
still performs current run/model/tool authority checks and serving-process
prewarm. Automated distribution, production deployment qualification and the
full borrowed-tool user journey remain separate completion gates.

### Automated service/distribution follow-up

Before an automated production controller may admit a new candidate, its host admission
service must independently revalidate template authorization, exact selected
source closures and their current grants, verify sealed members with actual
guest attempts, and commit a revocable admission record. It must distribute
verified bytes to the selected serving host, prewarm there, and bind serving
identity and route without rerouting ambiguous execution. Interrupted builds,
admission withdrawal, retries and cleanup require durable reconciliation.
This command does not implement those service/controller steps.

The public-seed `prepare_issuance_fixture` example remains explicitly test-only.
Neither its host-kernel discovery nor its allowlist creation is reused here.
Portable preparation tests use nonbootable byte fixtures intentionally: they
prove packaging/refusal and unchanged policy, not any hardware guarantee.
