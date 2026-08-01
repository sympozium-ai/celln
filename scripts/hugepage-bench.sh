#!/usr/bin/env bash
# hugepage-bench.sh — measure whether huge pages fix M1 spawn latency.
#
# docs/findings/m1-spawn.md measured spawn as page-fault-bound: a resuming cell
# takes ~2,511 copy-on-write faults at ~1.6 us each. On 2 MiB pages the same
# working set would be 5 faults. That is the prediction; this script tests it.
#
# It needs root, because both huge-page paths are host-global state:
#   * shmem THP policy — guest RAM is a memfd, and Fedora ships shmem THP off
#   * vm.nr_hugepages   — explicit hugetlbfs reservation
#
# Both are SAVED AND RESTORED on exit, including on failure. Nothing is left
# changed on your machine.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

THP=/sys/kernel/mm/transparent_hugepage/shmem_enabled
[ -w "$THP" ] || { echo "need root: re-run with sudo" >&2; exit 1; }

# Current value is the one in [brackets].
orig_thp=$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$THP")
orig_huge=$(cat /proc/sys/vm/nr_hugepages)
restore() {
  echo "$orig_thp" > "$THP" 2>/dev/null || true
  sysctl -q -w "vm.nr_hugepages=$orig_huge" 2>/dev/null || true
  printf '\nhost state restored: shmem_enabled=%s nr_hugepages=%s\n' "$orig_thp" "$orig_huge"
}
trap restore EXIT

# The benchmark must run as the invoking user: it needs /dev/kvm and the build
# tree, and running the whole toolchain as root would litter target/ with
# root-owned files.
run_as="${SUDO_USER:-$USER}"
bench() {
  local label="$1"; shift
  printf '\n\033[1;36m═══ %s\033[0m\n' "$label"
  sudo -u "$run_as" --preserve-env=NOUS_HUGEPAGE,NOUS_HUGETLB,PATH,HOME \
    env "$@" cargo run --quiet --release -p pilot --features kvm \
    --bin nous-bench-kvm 2>&1 |
    sed -n '/THESIS/,/memslot budget/p' |
    grep -vE 'memslot budget|^$' || true
}

echo "baseline: shmem_enabled=$orig_thp nr_hugepages=$orig_huge"
bench "A — baseline: 4 KiB pages" NOUS_X=1

echo advise > "$THP"
bench "B — shmem THP via MADV_HUGEPAGE" NOUS_HUGEPAGE=1

# 512 x 2 MiB = 1 GiB, enough for a 256 MiB mote plus its forks' private copies.
if sysctl -q -w vm.nr_hugepages=512 && [ "$(cat /proc/sys/vm/nr_hugepages)" -ge 256 ]; then
  bench "C — explicit hugetlbfs (MFD_HUGETLB)" NOUS_HUGETLB=1
else
  printf '\n\033[33mC skipped: could not reserve huge pages (fragmented memory?)\033[0m\n'
fi
