#!/usr/bin/env bash
# Separate hardware fixture: never packed into normal celln guest assets.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:?usage: bash scripts/mkparent-probe.sh /absolute/output.cpio}"
[[ "$out" = /* ]] || { echo 'output must be absolute' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 0755 "$work"
mkdir "$work/dev"
rustc --edition=2021 --target x86_64-unknown-linux-musl -C opt-level=2 \
  "$root/guest/probes/parent-mailbox.rs" -o "$work/init"
(cd "$work" && find . -print0 | cpio --null -o -H newc --owner=0:0 > "$out")
