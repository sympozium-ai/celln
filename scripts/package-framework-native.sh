#!/usr/bin/env bash
# Build static native guests from this exact checkout, then create one new
# operator package. This script neither installs nor deploys its output.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 ABSOLUTE_KERNEL NEW_ABSOLUTE_OUTPUT" >&2
  exit 2
fi

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kernel="$1"
output="$2"
case "$kernel:$output" in
  /*:/*) ;;
  *) echo "kernel and output must be absolute paths" >&2; exit 2 ;;
esac
[ ! -e "$output" ] || { echo "output already exists: $output" >&2; exit 2; }

revision="$(git -C "$repo" rev-parse HEAD)"
epoch="$(git -C "$repo" show -s --format=%ct HEAD)"
tree_sha256="sha256:$(git -C "$repo" ls-files --cached --others --exclude-standard -z \
  | sort -z | (cd "$repo" && xargs -0 sha256sum) | sha256sum | cut -d' ' -f1)"
target="${CARGO_TARGET_DIR:-$repo/target}"

cargo build --manifest-path "$repo/Cargo.toml" --locked --release \
  --target x86_64-unknown-linux-musl -p celln-pilot \
  --bin celln-pilot --bin pilot-fetch --bin celln-harness-json \
  --bin celln-harness-turn --bin celln-harness-parent --bin celln-uppercase
cargo build --manifest-path "$repo/Cargo.toml" --locked --release -p celln-cli --bin celln

"$target/release/celln" framework-package \
  --runtime-dir "$repo" \
  --guest-dir "$target/x86_64-unknown-linux-musl/release" \
  --kernel "$kernel" \
  --source-revision "$revision" \
  --source-tree-sha256 "$tree_sha256" \
  --source-epoch "$epoch" \
  --output "$output"
