# Ownership storage qualification

`ownership-probe.rs` checks cross-process lock exclusion and publication on the
filesystem actually mounted in two Pods. It is not a storage driver and cannot
turn independent node-local volumes into shared storage.

Compile without third-party dependencies:

```sh
rustc --edition 2021 --target x86_64-unknown-linux-musl \
  integrations/kubernetes/ownership-probe.rs -o ownership-probe
```

Include the binary in the test image and mount the candidate ownership PVC
writable by the intended router UID/GID (10001 in the Sympozium chart). Schedule
the two probe Pods on different eligible nodes. Use a **new, dedicated test
subdirectory**, never the live ledger. Publication uses create-new files and
will deliberately fail if a previous test record exists.

Run these operations through `kubectl --kubeconfig EXPLICIT_TEST_CONFIG exec`
with the same mounted directory argument on both Pods:

1. `ownership-probe publish DIRECTORY` on node A. Requires file fsync, atomic
   no-clobber hard-link publication, and directory fsync to succeed.
2. `ownership-probe hold DIRECTORY` on A. Wait for `LOCK_HELD` on stdout.
   The hold is bounded to 30 seconds.
3. While A is holding, `ownership-probe contend DIRECTORY` on B must succeed
   by observing `WouldBlock`. Unexpected lock acquisition or another errno is
   a test failure, not a supported storage backend.
4. Terminate the lock holder, then `ownership-probe read DIRECTORY` on B must
   reacquire the exclusive lock and read the exact published bytes.
5. In an explicitly disposable environment, repeat with simulated node loss,
   then restart the node and confirm the record remains visible from both.

These are necessary but not sufficient checks: storage power-loss durability,
network partitions, failover/fencing, full concurrent router claims, ambiguous
backend acceptance and long-term retention need separate tests. A Kind setup
with a common host Btrfs bind mount exercises multiple Kubernetes node
containers but shares one physical kernel and storage failure domain. Report
that scope; do not call it certification of NFS, a CSI driver, or independent
physical hosts. Never interrupt a production node to run this helper.
