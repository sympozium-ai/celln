#!/usr/bin/env bash
# Build an operator proof fixture from this checkout, never shared cached guest
# outputs. Does not load a credential, call a model, or mutate Kubernetes.
set -euo pipefail
[[ ( $# == 1 || ( $# == 2 && "$2" == --lifecycle ) ) && -n "$1" ]] || { echo 'usage: prepare-deployed-harness.sh CALLER [--lifecycle]' >&2; exit 2; }
package_mode=--package-only
fixture_options=()
if [[ ${2:-} == --lifecycle ]]; then
  package_mode=--lifecycle-package-only
  fixture_options=(--tool-only)
fi
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
[[ $(uname -s) == Linux ]] || { echo 'Unsupported: Linux required' >&2; exit 1; }
mkdir -p "$repo/target"
work=$(mktemp -d "$repo/target/deployed-harness.XXXXXX")
export CARGO_TARGET_DIR="$work/build"
export CELLN_PILOT_DIR="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release"
export TMPDIR="$work"
cd "$repo"
cargo build --locked --release --target x86_64-unknown-linux-musl \
  -p celln-pilot --bin celln-pilot --bin pilot-fetch --bin celln-harness-reference
cargo run --locked -p celln-pilot --features kvm --bin celln-harness-proof \
  -- "$package_mode" | tee "$work/package.log"
package=$(sed -n 's/^PACKAGED: //p' "$work/package.log")
[[ "$package" == "$work"/celln-harness-proof-* && -d "$package" ]]
cargo run --locked -p celln-cli --example prepare_harness_fixture -- \
  "$package" "$work/state" "$1" "${fixture_options[@]}"
git rev-parse HEAD > "$work/source-revision.txt"
git status --porcelain > "$work/source-status.txt"
sha256sum "$CELLN_PILOT_DIR/celln-pilot" "$CELLN_PILOT_DIR/pilot-fetch" \
  "$CELLN_PILOT_DIR/celln-harness-reference" > "$work/guest-binaries.sha256"
echo "Prepared: $work (no credentials or model requests)"
