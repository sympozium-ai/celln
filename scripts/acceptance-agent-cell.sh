#!/usr/bin/env bash
# Proves the public setup → ask → agent → ps flow without an API account.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${CELLN_BIN:-$root/target/debug/celln}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

[[ "$(uname -s)" = Linux ]] || { echo 'skip: agent-cell acceptance needs Linux'; exit 0; }
[[ -r /dev/kvm ]] || { echo 'skip: agent-cell acceptance needs readable /dev/kvm'; exit 0; }
[[ -x "$bin" ]] || { echo "need celln binary at $bin" >&2; exit 1; }

export PATH="$root/tests/fixtures:$PATH"
export CELLN_CONFIG="$work/config.toml"
export CELLN_ROOT="$work/state"

"$bin" setup --agent openai --no-json | grep -F 'default agent: openai'
"$bin" ask 'What is a binary tree?' --no-json | grep -F 'A binary tree stores'
"$bin" agent 'Print the acceptance marker.' --no-json | tee "$work/agent.out"
grep -F 'pilot: /agent/program permitted:agent' "$work/agent.out"
grep -F 'CELLN_ACCEPTANCE_OK' "$work/agent.out"
"$bin" ps -a --no-json | tee "$work/ps.out"
grep -E 'agent.*dissolved' "$work/ps.out"

echo 'acceptance: setup, question, sealed agent cell, output, and history passed'
