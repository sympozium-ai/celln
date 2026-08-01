#!/usr/bin/env bash
# mkinitramfs.sh — build the guest initramfs for boot testing.
#
# Compiles guest/init/init.c freestanding (no libc, raw syscalls) and packs it
# as an uncompressed newc cpio the kernel can unpack as its rootfs. Deliberately
# tiny and dependency-free: the point is a guest userspace we fully control, so
# guest-side claims are proven by guest code, not asserted from the host.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/target/nous-initramfs.cpio}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v gcc >/dev/null 2>&1 || { echo "gcc not found — needed to build the guest init" >&2; exit 1; }
command -v cpio >/dev/null 2>&1 || { echo "cpio not found — needed to pack the initramfs" >&2; exit 1; }

gcc -static -nostdlib -nostartfiles -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -Os -Wall -Wextra \
    -o "$work/init" "$root/guest/init/init.c"

# /dev must exist for init to mount devtmpfs onto it. Device nodes themselves
# cannot be created without privilege, which is why init mounts devtmpfs.
mkdir -p "$work/dev" "$work/tools"

mkdir -p "$(dirname "$out")"
( cd "$work" && find . -print0 | cpio --null -o -H newc --quiet ) > "$out"

printf 'initramfs: %s (%s bytes, init %s bytes)\n' \
  "$out" "$(stat -c%s "$out")" "$(stat -c%s "$work/init")"
