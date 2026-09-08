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

Before a production controller may use the candidate, the host admission
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
