# Actual deployed controller → router → KVM Harness proof

On 2026-09-07, `harness-deployed-proof-v2` succeeded in the isolated
`celln-deployed` Kind cluster. This is the **reference two-function Harness**,
not Pi/Hermes or a general-purpose supported Harness catalogue/UX.

## Verified path and result

Actual in-cluster Sympozium controller (`b331a29`) → DNS/Service
`celln-router.celln-system.svc.cluster.local:8787` → one of two chart-deployed
router replicas with shared durable ownership → stable dispatcher Service →
dispatcher on `celln-deployed-worker` → KVM cell → mediated DeepSeek requests.
No port-forward was used for execution or audit retrieval. The controller used
the chart's RBAC and explicit experimental Harness gate, not admin kubeconfig.

The model called `add(["37","5"])`, received `42`, then called
`multiply(["42","2"])`, received `84`, and answered **84**. The response model
was `deepseek-v4-flash` for the approved requested alias `deepseek-chat`.

- AgentRun phase: Succeeded; no Kubernetes Job created.
- Receipt: v1alpha2, cell `f3fe8616650b`, matches controller receipt exactly.
- Broker: 3 requests, 0 denied, 1710 response bytes.
- Audit contains operator model grant, tool closure, agent lane and Dissolved.
- Both dispatchers reported zero live cells after completion.
- Both router Pods were restarted; the complete same audit was retrieved
  through the Service and compared equal afterwards. No new model request was
  submitted for that check.
- Started 10:40:43 UTC, completed 10:40:53 UTC. Resolving lasted about seven
  seconds on this first request while preparing the warm template. This is
  **not** a warm steady-state latency measurement or proof that cold preparation
  is absent from the first request's latency.

Controller binary SHA-256:
`94f1f046c99609df44f4d8163f688203c4b5b736e7fa9631a02e735d320c94c5`.
Router/dispatcher CLI source is the combined `bb1e718` build recorded in earlier
deployment evidence. Guest `pilot-fetch` SHA-256:
`9594ce92c29289c439d829272eec0942e4894f02abf4585e2c57b60632c6ed84`.
Companion JSON records the successful frozen request/result/receipt and audit.

## Initial failure and build correction

The first AgentRun (`harness-deployed-proof`) failed with `guest exited with
code 1`; output was `pilot-fetch: CELLN_FETCH_ERROR:only https URLs are permitted`.
The guest `pilot-fetch` copied from a shared cross-worktree release directory
did not contain the required `--json-stdin` support. The host broker correctly
denied the resulting non-HTTPS request. Its audit showed one request, one denial
and zero response bytes. The failed execution and owner record were retained.

All three guest binaries were rebuilt in this checkout's isolated target, then
a fresh signed package/grant was generated for the distinct `-v2` AgentRun.
No failed execution ID was replayed and no ambiguous provider transaction was
retried. The new preparation script builds all guest binaries in a newly
allocated target directory and records their hashes to prevent reuse of that
stale shared output. This was a build-artifact mismatch, not grounds to bypass
the broker's HTTPS enforcement.

The new script was run end-to-end with caller
`test:nonbillable-preparation-check`; fresh guest builds, signed packaging and
fixture generation passed under `target/deployed-harness.DwRwbF`. Invoke it as
`bash integrations/kubernetes/prepare-deployed-harness.sh CALLER`.

## Credential cleanup and limits

The user-authorized DeepSeek key was parsed as a bounded literal from `.zshrc`
without sourcing that file or printing the key. A mode-0600 temporary copy was
used to create the test Secret and immediately removed. After completion, the
Secret was deleted; both dispatcher mounts were checked until their token file
was absent. `.zshrc` was not changed. No credential is part of these artifacts.

Transport remains explicitly acknowledged plaintext inside an isolated,
policy-enforcing test cluster; this is not TLS acceptance. Dispatcher Pods use
test-only privilege for KVM access. Two dispatcher nodes were present, but this
successful model execution was on one node (the earlier failed cell was on the
other). This does not prove concurrent two-node successful AI, live cancellation,
in-flight replica/node loss, exactly-once external effects, general tool
admission, full Harness support, Helm upgrade/rollback or product UX completion.
Sympozium epic #426 remains open.

Persistent raw evidence and cluster fixtures:
`target/deployed-kind.JcI9Gg/evidence/`. Both AgentRuns remain for inspection;
the controller and dispatcher/router deployments remain running without a model
credential. The next work is adversarial lifecycle checks and the remaining
execution-plane/product requirements, not treating this reference proof as the
finished Harness + Celln offering.
