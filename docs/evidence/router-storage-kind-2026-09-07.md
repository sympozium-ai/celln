# Shared ownership storage: isolated Kind evidence

Source checkpoint: `c96cba6`. Helper:
`integrations/kubernetes/ownership-probe.rs`. Actual checks performed after
the user-requested host reboot, on 2026-09-07.

## Topology and recovery

- Cluster: `celln-deployed`, Kubernetes v1.35.0, rootless Podman.
- Both workers bind the same host Btrfs directory into their node containers.
- Retained PV `celln-kind-shared-ownership`, PVC
  `celln-system/celln-router-ownership`, RWX; explicit worker node affinity.
- Pods `storage-a` on `celln-deployed-worker` and `storage-b` on
  `celln-deployed-worker2`, non-root UID/GID 10001.
- Image `localhost/celln-storage-proof:bb1e718`; includes the static helper.
- Dedicated test subdirectory `/ownership/resume-proof-1`, separate from any
  execution ownership records.

All three test node containers were confirmed Exited after reboot, then
started without recreating the cluster, PVC or directory. Early transient API
RBAC/network errors cleared during control-plane recovery. All cluster Pods
were Running/ready at the end, including Calico, both storage Pods and DNS.
The older `celln-m0` cluster remained stopped; Framework was untouched.

## Observed sequence

| Operation | Actual result |
|---|---|
| A: `publish /ownership/resume-proof-1` | File fsync, no-clobber hard-link publication and directory fsync succeeded |
| A: `hold /ownership/resume-proof-1` | Printed `LOCK_HELD` |
| B: `contend /ownership/resume-proof-1` during A's hold | Observed `WouldBlock`; did not acquire the lock |
| Host: `podman kill --signal KILL celln-deployed-worker` | Test worker container killed |
| B: `read /ownership/resume-proof-1` before restarting A | Reacquired lock and read exact published bytes |
| Host: `podman start celln-deployed-worker` | Existing worker restarted |
| A and B: repeat `read` after A's Pod recovered | Both reacquired the lock and read the same record |

The `hold` process has a bounded 30-second lifetime; the contention, node kill
and survivor read were performed immediately after `LOCK_HELD`, within that
window. The survivor read completed before restarting the killed node. At the
end A's Pod restart count was 2 (host reboot plus simulated node kill), B's was
1 (host reboot), and all three Kubernetes nodes were Ready.

## Scope limits

This verifies the required basic filesystem operations across the two node
containers and lock release/record visibility after simulated node loss. It
does **not** certify power-loss durability, separate physical kernels, network
partition fencing, an NFS/CSI implementation, or automatic dispatcher failover.
The record was created after reboot, so this does not claim that this test
record survived the host reboot.

Actual router replicas have not yet exercised the PVC. Controller → Service →
router → two KVM dispatchers and their retry/cancellation behavior remain
separate acceptance gates. Keep Sympozium epic #426 open.
