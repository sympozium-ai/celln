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
out="${1:-$root/target/celln-toolfs.img}"
# 32 MiB: comfortably above the pmem namespace minimum, 2 MiB-aligned sizing
# keeps the DAX mapping path happy, and it leaves room for a real binary — a
# static musl Rust program is a few MiB before it has done anything.
size_mb="${2:-32}"
# Anything further on the command line is a real tool to seal in, copied to the
# image root under its own basename. This is how a program the host attested
# gets into the cell: as bytes in a filesystem that is lent read-only, never as
# something written from inside.
shift 2 2>/dev/null || true
extras=("$@")

command -v mke2fs >/dev/null 2>&1 || { echo "mke2fs not found (e2fsprogs)" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root"
# Production sealed roots provide /tmp for pilot's per-cell scratch mount. The
# tiny proof image must exercise that same chrooted path rather than executing
# across the outer /tools mount.
mkdir -m 1777 "$work/root/tmp"

# The probe tool. Layout is shared with warden::vmm::boot::probe_tool and with
# guest/init/init.c; the magic is what makes drift between the three fail loudly
# instead of silently passing.
#   +0  "CELLNTOOL"        magic — "I mapped the sealed page-set"
#   +16 mov eax,0x5a; ret a function the guest calls out of the mapping
{
  printf 'CELLNTOOL'
  printf '\0\0\0\0\0\0\0'
  printf '\xb8\x5a\x00\x00\x00\xc3'
} > "$work/root/probe"
# Pad to a full page so the mapping covers allocated blocks.
truncate -s 4096 "$work/root/probe"

for f in ${extras[@]+"${extras[@]}"}; do
  [ -r "$f" ] || { echo "mktoolfs: cannot read $f" >&2; exit 1; }
  install -m 0755 "$f" "$work/root/$(basename "$f")"
done

mkdir -p "$(dirname "$out")"
rm -f "$out"
mke2fs -q -t ext2 -b 4096 -d "$work/root" -F "$out" "$((size_mb * 256))" >/dev/null

# Fail loudly here rather than in a guest three layers down.
if ! grep -q CELLNTOOL "$out"; then
  echo "toolfs image does not contain the probe magic — mke2fs -d did not populate it" >&2
  exit 1
fi

printf 'toolfs: %s (%s bytes, ext2, contains /probe)\n' "$out" "$(stat -c%s "$out")"
