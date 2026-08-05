#!/usr/bin/env bash
set -euo pipefail

# ── Celln Multi-Agent DeepSeek Benchmark ────────────────────────────
# Kicks off N concurrent agents through the celln architecture using
# DeepSeek as the LLM provider. Each agent writes a single-file Rust
# program, it gets built (forged), sealed into a hardware-isolated
# microVM, and executed. Every stage is timed and reported.
#
# Usage:
#   export DEEPSEEK_API_KEY=sk-...
#   ./scripts/benchmark-deepseek-agents.sh [--agents N] [--timeout S]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CELLN_BIN="${REPO_ROOT}/target/release/celln"
OUT_DIR="${REPO_ROOT}/target/benchmark-deepseek-agents"
RESULT_FILE="${OUT_DIR}/results.json"

AGENTS=5
TIMEOUT=180
MODEL="${DEEPSEEK_MODEL:-deepseek-chat}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agents) AGENTS="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    *) echo "unknown flag: $1"; exit 1 ;;
  esac
done

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "fatal: DEEPSEEK_API_KEY is not set" >&2
  exit 1
fi

export PATH="${REPO_ROOT}/scripts:${REPO_ROOT}/tests/fixtures:$PATH"
export CELLN_RUNTIME_DIR="$REPO_ROOT"

mkdir -p "$OUT_DIR"

echo "══════════════════════════════════════════════════════════════════"
echo "  Celln Multi-Agent Benchmark"
echo "  Provider:  DeepSeek"
echo "  Model:     $MODEL"
echo "  Agents:    $AGENTS"
echo "  Timeout:   ${TIMEOUT}s per agent"
echo "  Output:    $RESULT_FILE"
echo "══════════════════════════════════════════════════════════════════"
echo ""

# ── prerequisite checks ────────────────────────────────────────────
if [[ ! -x "$CELLN_BIN" ]]; then
  echo "building celln..."
  (cd "$REPO_ROOT" && cargo build --release -p celln-cli)
fi

echo "=== Health Check ==="
"$CELLN_BIN" doctor 2>&1 || true
echo ""

# ── configure deepseek as default ───────────────────────────────────
echo "=== Setting DeepSeek as default backend ==="
"$CELLN_BIN" agents --set-default deepseek 2>&1
echo ""

# ── research tasks ──────────────────────────────────────────────────
# Each task asks the agent to write a single-file Rust program that
# demonstrates computation inside a sealed cell.
TASKS=(
  "Implement three sorting algorithms (quicksort, mergesort, insertion sort) and benchmark them on a random i32 array of size 10000. Print the algorithm name and elapsed microseconds for each."
  "Implement a concurrent prime-number sieve. Spawn 4 threads that each scan a segment of 1..100000 for primes using trial division. Merge the results and print the count and the largest prime found."
  "Compute the SHA-256 digest of a hardcoded input string, then verify it matches a given hex hash. Print 'MATCH' or 'MISMATCH'. Use only std; write the SHA-256 compression from scratch (no external crates)."
  "Parse a hardcoded TOML-like configuration string, extract key-value pairs, and print a sorted, indented summary. The config string is multiline with sections like [server] and [database]."
  "Simulate a 1D random walk with 1,000,000 steps. At each step the walker moves +1 or -1 with equal probability. Compute the final position, the maximum displacement reached, and the fraction of time spent positive. Print all three values."
)

# If fewer agents were requested, slice the task list
if [[ $AGENTS -lt ${#TASKS[@]} ]]; then
  TASKS=("${TASKS[@]:0:$AGENTS}")
fi

# ── warm-up: single agent to prime caches ───────────────────────────
echo "=== Warm-up (single agent) ==="
WARMUP_START=$(date +%s%3N)
set +e
"$CELLN_BIN" agent "${TASKS[0]}" \
  --agent deepseek \
  --model "$MODEL" \
  --timeout "$TIMEOUT" \
  &> "$OUT_DIR/warmup.log"
WARMUP_EXIT=$?
set -e
WARMUP_END=$(date +%s%3N)
WARMUP_MS=$((WARMUP_END - WARMUP_START))
echo "  warm-up completed in ${WARMUP_MS}ms (exit $WARMUP_EXIT)"
echo ""

# ── concurrent benchmark run ────────────────────────────────────────
echo "=== Concurrent Agent Run ($AGENTS agents) ==="
BENCH_START=$(date +%s%3N)
PIDS=()

for i in $(seq 1 $AGENTS); do
  TASK_INDEX=$((i - 1))
  TASK="${TASKS[$TASK_INDEX]}"
  LOG_FILE="$OUT_DIR/agent-${i}.log"
  TIMING_FILE="$OUT_DIR/agent-${i}.timing"

  (
    AGENT_START=$(date +%s%3N)
    set +e
    "$CELLN_BIN" agent "$TASK" \
      --agent deepseek \
      --model "$MODEL" \
      --timeout "$TIMEOUT" \
      > "$LOG_FILE" 2>&1
    EXIT_CODE=$?
    set -e
    AGENT_END=$(date +%s%3N)
    DURATION_MS=$((AGENT_END - AGENT_START))
    echo "{\"agent\":$i,\"exit_code\":$EXIT_CODE,\"duration_ms\":$DURATION_MS,\"task\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$TASK")}" > "$TIMING_FILE"
    echo "[agent-$i] done in ${DURATION_MS}ms (exit $EXIT_CODE)"
  ) &
  PIDS+=($!)
done

FAILURES=0
for pid in "${PIDS[@]}"; do
  if ! wait "$pid"; then
    FAILURES=$((FAILURES + 1))
  fi
done

BENCH_END=$(date +%s%3N)
BENCH_WALL_MS=$((BENCH_END - BENCH_START))

echo ""
echo "=== Results ==="
echo ""

# ── collate results ─────────────────────────────────────────────────
declare -a AGENT_RESULTS=()
GLOBAL_EXIT=0
PARSE_ERROR=0

for i in $(seq 1 $AGENTS); do
  TIMING_FILE="$OUT_DIR/agent-${i}.timing"
  LOG_FILE="$OUT_DIR/agent-${i}.log"

  if [[ -f "$TIMING_FILE" ]]; then
    AGENT_RESULTS+=("$(cat "$TIMING_FILE")")
  else
    AGENT_RESULTS+=("{\"agent\":$i,\"exit_code\":-1,\"duration_ms\":0,\"task\":\"unknown\",\"error\":\"no timing file\"}")
    PARSE_ERROR=$((PARSE_ERROR + 1))
  fi

  echo "── agent $i ──"
  if [[ -f "$TIMING_FILE" ]]; then
    python3 -c "
import json
with open('$TIMING_FILE') as f:
    d = json.load(f)
print(f'  exit={d[\"exit_code\"]}  wall={d[\"duration_ms\"]}ms')
" 2>/dev/null || echo "  (unable to parse timing)"
  fi

  # Show key lines from output
  if [[ -f "$LOG_FILE" ]]; then
    grep -E '(pilot:|replied|admitted|CELL_ACCEPT|CELLN:)' "$LOG_FILE" 2>/dev/null | head -8 || true
    echo ""
  fi
done

echo "── summary ──"
echo "  agents: $AGENTS"
echo "  wall clock: ${BENCH_WALL_MS}ms"
echo "  failures: $FAILURES"

# ── write JSON report ───────────────────────────────────────────────
python3 -c "
import json, sys, os

hostname = '$(hostname)'
kernel = '$(uname -r)'
agents = []

for i in range(1, $AGENTS + 1):
    tf = os.path.join('$OUT_DIR', f'agent-{i}.timing')
    lf = os.path.join('$OUT_DIR', f'agent-{i}.log')
    if os.path.exists(tf):
        with open(tf) as f:
            d = json.load(f)
        d['log_path'] = lf
        agents.append(d)
    else:
        agents.append({'agent': i, 'exit_code': -1, 'duration_ms': 0, 'error': 'missing'})

report = {
    'provider': 'deepseek',
    'model': '$MODEL',
    'agents_requested': $AGENTS,
    'host': hostname,
    'kernel': kernel,
    'wall_clock_ms': $BENCH_WALL_MS,
    'warmup_ms': $WARMUP_MS,
    'failures': $FAILURES,
    'agent_results': agents,
}

with open('$RESULT_FILE', 'w') as f:
    json.dump(report, f, indent=2)

print(json.dumps(report, indent=2))
" 2>/dev/null

echo ""
echo "Report written to $RESULT_FILE"

exit $FAILURES
