# Reboot checkpoint — 2026-09-07

**Resumed after user confirmation.** Shared-storage checks subsequently passed;
see `docs/evidence/router-storage-kind-2026-09-07.md`. The historical checkpoint
below describes the state at pause, not the latest test results.

Work paused at the user's request. Epic sympozium-ai/sympozium#426 remains
incomplete; do not resume testing until the user asks. No test or model request
is running. No simulated node failure has been performed.

## Latest state

- Celln worktree: `/home/axjns/Code/celln-worktrees/harness-model-broker`, branch
  `test/harness-router-deployed`. Combined source merge `bb1e718`, startup
  evidence `a9edf9b`. This checkpoint adds the storage probe and instructions.
- Sympozium chart worktree: `/home/axjns/Code/sympozium-m0-celln`, branch
  `fix/celln-router-deployment`, commit `fe09549`, draft PR #429 on #427.
- Existing Harness binding: Sympozium PR #428, Celln PRs #71–74.
- Durable router ownership: Celln PR #75 on #70. None were merged on GitHub
  during this deployment work.

## Persistent test resources

New isolated Kind cluster `celln-deployed`: all three nodes Ready at pause.
Both `celln-system/storage-a` and `storage-b` were Running on different workers.
Their main processes only sleep; **no storage probe operations have run yet**.
The earlier readiness waits timed out during Calico image pulls, but the final
inspection confirmed recovery. Do not recreate the cluster merely because the
waits timed out.

Persistent fixture directory (Btrfs, not /tmp):

`/home/axjns/Code/celln-worktrees/harness-model-broker/target/deployed-kind.JcI9Gg`

Contains `kubeconfig`, `kind.yaml`, `storage.yaml`, and `ownership/`. Both workers
bind-mount this exact host ownership directory at `/celln-shared-ownership`.
PVC `celln-system/celln-router-ownership` is Bound to retained PV
`celln-kind-shared-ownership`. The directory is mapped to container UID/GID
10001 through Podman's user namespace. Do not purge it or change permissions
indiscriminately. This is a one-host Kind storage topology, not a multi-host
storage certification.

Original isolated cluster `celln-m0` was left untouched. Its kubeconfig and
Calico installation inputs were copied out of /tmp into the persistent
`target/reboot-checkpoint/` directory in this worktree. Framework was untouched.
Always pass the explicit isolated kubeconfig; never use the default context.

Persistent Podman images:

- `localhost/celln-deployed:bb1e718`: combined static router/Harness CLI.
- `localhost/celln-storage-proof:bb1e718`: above plus `ownership-probe`.

Clean build output: `target/deployed/`. Do not reuse the older cross-worktree
Cargo target, which supplied stale dependency artifacts in the first build.
Temporary archives and previous raw AI artifacts under /tmp may not survive
reboot; committed evidence remains authoritative. No provider token was staged
for this storage/startup work.

## Resume

1. Inspect Podman containers, both isolated kubeconfigs and nodes after reboot;
   restore stopped owned containers if needed, without recreating state.
2. Follow `integrations/kubernetes/OWNERSHIP_QUALIFICATION.md`: publish from
   storage-a, hold its lock, contend from storage-b, release/reacquire/read.
   Then perform the explicitly scoped disposable-node loss check.
3. Record actual outcomes. Presently none of these storage semantics are proven.
4. Deploy the actual routers and two KVM dispatchers, then the controller and
   real Harness run through the Service path. The startup smoke was only
   port-forward + emptyDir and cannot stand in for this acceptance gate.
5. Continue the full epic, including TLS/authenticated capabilities, host
   lifecycle, supported Harness/tool admission, UX and end-to-end regressions.
