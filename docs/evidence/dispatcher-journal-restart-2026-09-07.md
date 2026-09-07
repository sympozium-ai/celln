# Deployed terminal journal survives owner-node restart

Tested Celln `463356c` (PR #78) in the existing isolated `celln-deployed` Kind
cluster. Both dispatchers had zero live cells before their image upgrade. No
model credential was present or used. Pre-upgrade memory-only history was not
invented or imported; previous evidence remains committed separately.

New dispatcher image: `localhost/celln-dispatcher-journal:463356c`.
Image config digest:
`sha256:9357a4d57647a9bd794fff7bca337bd1112852e8e1aad8da998edcc72327b6df`.
Static CLI SHA-256:
`679ffe172a0329bfb78403e0ccb828b553b5cb36ee234c69f201b111b3bcb305`.
The controller/router versions and transport restrictions are unchanged from
the prior deployed proof. Rollout exceeded the 45-second observation timeout
but completed normally; no state was recreated because of that timeout.

## Actual sequence

1. Submit `journal-terminal-proof` through the actual in-cluster controller and
   router Service using the non-networked lifecycle tool and a 20-second limit.
2. Observe AgentRun Failed with `execution deadline exceeded`, cell
   `3643ebb82e76` on `celln-deployed-worker2`, 11:19:40–11:20:00 UTC. The result
   contains `CELLN_LIFECYCLE_STARTED`, showing the guest tool actually ran.
3. Fetch its full audit through the Service and verify the failed receipt and
   Dissolved event before touching the owning node.
4. SIGKILL the disposable Kind worker container `celln-deployed-worker2`, then
   restart that same container. Existing persistent state and journal remain.
5. Confirm dispatcher-0 is ready with container restart count 1. Fetch the audit
   through the Service again and compare the complete JSON equal to the original.
6. Repost the controller's **exact frozen request bytes** directly to the
   authenticated dispatcher. Compare the returned receipt with the original;
   it is identical. This deliberately exercises dispatcher replay protection,
   not merely the router's independent retry-as-GET behavior.
7. POST cancellation through the router Service. The terminal response equals
   the retry response; a failed receipt is not relabelled cancelled.
8. The restarted dispatcher reports zero live cells and an empty warm cache,
   consistent with no new execution launched by retrieval/retry/cancellation.

The companion JSON contains the original AgentRun status/receipt, before/after
audits, retry and cancellation responses. Raw artifacts are also retained under
`target/deployed-kind.JcI9Gg/evidence/journal-*`.

## Limits and continuation

This proves retrieval of a **durably completed** real KVM execution after its
owner's process/node-container restart. It does not prove power-loss durability
on separate physical hosts, automatic recovery of an interrupted execution,
provider side-effect reconciliation or production TLS/storage qualification.
An unfinished admission claim still conservatively returns 503 and needs
operator reconciliation; that separate state must not be labelled cancelled
or replayed. The larger Harness/BYO-tool/UX epic remains open.
