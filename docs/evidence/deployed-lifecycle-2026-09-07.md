# Deployed guest cancellation, deadline and router replacement

Actual tests on the existing isolated `celln-deployed` Kind cluster. The
in-cluster controller, router Service/shared ledger and two KVM dispatchers are
the same deployed binaries recorded in the reference Harness AI proof.

These tests use a separately compiled **non-AI tool**: it prints and flushes
`CELLN_LIFECYCLE_STARTED`, sleeps 120 seconds, then prints an unexpected-completion
marker. It is packaged as `/harness` solely to reuse the signed test package
layout; it is not the reference Harness runtime or a provider simulation. All
requests use v1alpha1 tool lane, no egress and no model grant. The model Secret
remained absent throughout. The AgentRun's legacy model fields do not supply
model authority to these tool-only requests.

## Observed results

| Case | Evidence |
|---|---|
| Delete running AgentRun | Running status and one live cell observed; deletion timestamp and finalizer captured while cleanup was pending; remote terminal receipt `cancelled`; AgentRun subsequently absent |
| 20-second timeout | AgentRun Failed with `execution deadline exceeded`; receipt 10:48:53–10:49:13 UTC; cell output hash matches the guest-start marker |
| Restart both routers while run active, then delete | Both replacement router Pods became ready; AgentRun remained Running; deletion through the replacement routers produced a cancelled receipt and completed |

Deletion's cell was `51e11cf844e8` on worker2. Timeout's was `2fc883f00872` on
worker. Router-replacement cancellation's was `46e740b833e4` on worker2.
Both cancellation terminal records contain exactly the guest-start marker,
not the unexpected completion marker. All three audits fetched through the
Service contain Dissolved. After all cases both dispatchers reported zero live
cells. No Kubernetes Job was used for execution.

The third run started 10:50:09 UTC and was cancelled at 10:50:53 UTC, before its
90-second limit and before the tool's 120-second sleep could finish. Thus the
terminal cancellation is not merely natural completion after router restart.

## Reproduction and artifacts

Fixture sources: `crates/celln-pilot/tests/fixtures/lifecycle_tool.rs` and
`celln-harness-proof --lifecycle-package-only`. State preparation uses
`prepare_harness_fixture ... --tool-only`, which omits model-grant files and
clears request egress/Harness binding. Both commands were executed successfully
to produce the deployed fixture. The fresh-build wrapper supports:

```sh
bash integrations/kubernetes/prepare-deployed-harness.sh test:lifecycle --lifecycle
```

The wrapper was also executed end-to-end successfully with caller
`test:lifecycle-wrapper-check`, producing `target/deployed-harness.b4xsAf/state`.

Submit the resulting mote/tools/invocation as a Celln AgentRun in tool lane;
use timeout 90s for deletion/restart and 20s for deadline. Wait for actual live
execution before deletion. Do not reinterpret a failed/pending admission as a
cancellation test. The retained router owner records must not be deleted or
replayed under the same IDs.

Raw requests, statuses, terminal records and audits are under persistent
`target/deployed-kind.JcI9Gg/evidence/lifecycle-*`; the companion JSON captures
the durable evidence. Deleted runs are intentionally absent; timeout and
earlier model runs remain for inspection. No test execution remains active.
`CARGO_TARGET_DIR=target/deployed make ci` passed after the fixture changes.

## Remaining scope

This covers actual guest-tool teardown and router replacement during an active
execution. It does not prove interruption during a live provider POST, provider
side-effect reconciliation, dispatcher-node loss, transport failure during
cancellation, or production storage/TLS behavior. Those remain distinct gates
alongside the broader Harness/BYO-tool admission and UX work in epic #426.
