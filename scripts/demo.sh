#!/usr/bin/env bash
# demo.sh — build and run the five-beat proof loop, then a CLI smoke test.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building"
cargo build --quiet

echo "==> five-beat proof (mock mode)"
cargo run --quiet --bin nous-demo

echo
echo "==> assay CLI smoke test"
ROOT="$(mktemp -d)"
run() { cargo run --quiet --bin assay -- --root "$ROOT" "$@"; }

# stand in a couple of "tool" blobs
printf 'cpython-bytes' > "$ROOT/python.bin"
printf 'leftpad-bytes' > "$ROOT/leftpad.bin"

run init
run admit /usr/bin/python "$ROOT/python.bin" --interpreter
run resolve /usr/bin/python "$ROOT/python.bin" --interpreter   # warm hit
run resolve /usr/lib/leftpad "$ROOT/leftpad.bin"               # cold -> verified
run rebuild                                                    # -> forged
run status

rm -rf "$ROOT"
echo
echo "done."
