# Combined router/Harness container startup

Scope: actual startup of the merged router/Harness binary in the isolated
`kind-celln-m0` cluster. **Not** shared-storage, controller, backend execution,
TLS, network-policy or KVM acceptance evidence.

- Integration source: `bb1e718` (merges `577699d` router ownership into
  `d92651e` Harness dispatch); clean at build time.
- Build: `CARGO_TARGET_DIR=target/deployed cargo build -p celln-cli
  --target x86_64-unknown-linux-musl` (development profile).
- Binary SHA-256: `b2e3da347f72046b85137d7eda540eee4e92838e80af85ee896174828f7b74c6`.
- Containerfile: `integrations/kubernetes/Dockerfile`, copied with the static
  binary into `/tmp/celln-deployed-image.zZtd30`.
- Local image: `localhost/celln-deployed:bb1e718`.
- Podman manifest digest:
  `sha256:973336b54bb56be241ed46aa0057c8e52b209a96ba6cbf3b625f1912a7a72a92`.
- Kubernetes reported image ID (config digest, not manifest digest):
  `sha256:dab2eabd09e5ebc8d705463ecda9383bf8622897770065df12d369b95a0d9224`.
- Image imported with `kind load image-archive` using the Podman provider;
  `kind load docker-image` failed to discover the local image. The archive
  path worked; no registry publication was performed.
- Worker: `celln-m0-worker`, Kubernetes v1.35.0.
- Pod: `celln-router-smoke/router-startup`; no service-account mount, UID/GID
  10001, fsGroup 10001, RuntimeDefault seccomp, all capabilities dropped,
  no privilege escalation, read-only root filesystem.
- Two public dummy credentials projected read-only with mode 0440. No provider
  credential or billable model request was involved.
- Ownership used **emptyDir for startup only**. This intentionally does not
  satisfy the required persistent shared ownership contract.

Observed process log:

```text
celln route listening on 0.0.0.0:8788 (1 backends, RoundRobin)
```

Actual HTTP checks through kubectl port-forward:

| Request | Observed status and body |
|---|---|
| GET `/v1/executions/smoke`, no credential | 401 `{"error":"unauthorized"}` |
| Same GET, correct public test client token | 404 `{"error":"unknown execution"}` |

This proves the static binary can start with the chart's non-root/read-only
settings and read projected credentials. Port-forward bypasses Service routing
and is not an ingress-policy test. The backend was deliberately absent, so no
execution success is implied. Startup fixture and image archive remain under
`/tmp/celln-deployed-image.zZtd30`; the smoke namespace was removed after checks.

The clean integration build also passed all 15 `cargo test -p celln-cli
router::` tests. A first attempt using a target directory shared with older
worktrees linked stale `celln-spec` artifacts; rebuilding with the isolated
`target/deployed` directory succeeded without source changes. Use isolated
build outputs for subsequent deployed proofs.

Remaining: actual shared-filesystem qualification, stable two-dispatcher
ownership, controller → Service → router → KVM, node/replica loss, cancellation,
TLS, authenticated capability reporting and host lifecycle tests. Epic #426
remains open.
