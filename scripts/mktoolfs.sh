#!/usr/bin/env bash
# mktoolfs.sh — build the sealed tool filesystem image.
#
# This is the host-side half of the production-shaped join: a real filesystem,
# built before sealing, containing a tool the guest opens by path. It is built
# read-only-by-construction (nothing ever mounts it here) because the region it
# gets sealed into is read-only to the guest — the image has to be complete
# before it is lent.
#
# ext2 rather than ext4: no journal, so a guest mounting it read-write never
# tries to replay one against a device that silently drops writes.
#
# mke2fs -d populates the image from a directory without needing root or a
# loopback mount.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/target/nous-toolfs.img}"
# 16 MiB: comfortably above the pmem namespace minimum, and 2 MiB-aligned
# sizing keeps the DAX mapping path happy.
size_mb="${2:-16}"

command -v mke2fs >/dev/null 2>&1 || { echo "mke2fs not found (e2fsprogs)" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root"

# The probe tool. Layout is shared with warden::vmm::boot::probe_tool and with
# guest/init/init.c; the magic is what makes drift between the three fail loudly
# instead of silently passing.
#   +0  "NOUSTOOL"        magic — "I mapped the sealed page-set"
#   +16 mov eax,0x5a; ret a function the guest calls out of the mapping
{
  printf 'NOUSTOOL'
  printf '\0\0\0\0\0\0\0\0'
  printf '\xb8\x5a\x00\x00\x00\xc3'
} > "$work/root/probe"
# Pad to a full page so the mapping covers allocated blocks.
truncate -s 4096 "$work/root/probe"

mkdir -p "$(dirname "$out")"
rm -f "$out"
mke2fs -q -t ext2 -b 4096 -d "$work/root" -F "$out" "$((size_mb * 256))" >/dev/null

# Fail loudly here rather than in a guest three layers down.
if ! grep -q NOUSTOOL "$out"; then
  echo "toolfs image does not contain the probe magic — mke2fs -d did not populate it" >&2
  exit 1
fi

printf 'toolfs: %s (%s bytes, ext2, contains /probe)\n' "$out" "$(stat -c%s "$out")"
