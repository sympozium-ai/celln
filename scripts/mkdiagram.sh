#!/usr/bin/env bash
# mkdiagram.sh — render the stack diagram for the README.
#
# Emits docs/assets/stack.gif (animated) and stack.png (a still, for anywhere
# that will not play a GIF).
#
# Frames are authored as SVG here, rasterised with rsvg-convert, and assembled
# by ffmpeg with a generated palette — a shared palette keeps a flat-colour
# diagram crisp and the file small. Shell for glue, per AGENTS.md.
#
# The animation tells the five-beat story, because a static box diagram of a
# host and a guest looks like every other box diagram. What is worth showing is
# the *movement*: a tool being lent, sealed, demoted, and revoked.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/docs/assets"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v rsvg-convert >/dev/null || { echo "need rsvg-convert (librsvg)" >&2; exit 1; }
command -v ffmpeg       >/dev/null || { echo "need ffmpeg" >&2; exit 1; }
mkdir -p "$out"

W=900; H=430
BG="#14120f"       # warm near-black; readable on light and dark READMEs alike
PANEL="#1c1915"
INK="#f2eee6"      # cream
DIM="#8b8477"
ACCENT="#c24a1a"   # burnt orange — attested, sealed, ours
WARN="#e8553d"     # refused
OK="#7fa650"       # permitted

# frame(index, cell_op, tool_x, tool_op, sealed, agent_op, strike_op, revoke_op,
#       lane, caption, beat)
#
# Discrete states with a few tween frames between them: a stack diagram reads
# better as deliberate steps than as constant motion.
frame() {
  local i="$1" cell_op="$2" tool_x="$3" tool_op="$4" sealed="$5" agent_op="$6" \
        strike_op="$7" revoke_op="$8" lane="$9" caption="${10}" beat="${11}"

  local seal_stroke="$DIM" seal_w=1 tool_sub="verified"
  if [ "$sealed" = "1" ]; then
    seal_stroke="$ACCENT"; seal_w=2
    # Say r-x on the tool itself. A floating badge collided with the path.
    tool_sub="verified · r-x"
  fi

  local lane_fill="$DIM" lane_text=""
  case "$lane" in
    tool) lane_fill="$OK";   lane_text="tool lane" ;;
    data) lane_fill="$WARN"; lane_text="data lane · demoted" ;;
  esac

  cat > "$work/f$(printf '%03d' "$i").svg" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="$W" height="$H" viewBox="0 0 $W $H">
  <rect width="$W" height="$H" fill="$BG"/>

  <!-- wordmark -->
  <text x="40" y="52" font-family="DejaVu Sans Mono" font-size="21" fill="$INK" letter-spacing="1.5">nouscell</text>
  <text x="40" y="74" font-family="DejaVu Sans Mono" font-size="12.5" fill="$DIM">every tool is memory the host lends in — and can take back</text>

  <!-- ── host ─────────────────────────────────────────── -->
  <text x="40" y="126" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM" letter-spacing="2">HOST</text>
  <rect x="40" y="140" width="250" height="62" rx="4" fill="$PANEL" stroke="$DIM" stroke-width="1"/>
  <text x="58" y="167" font-family="DejaVu Sans Mono" font-size="14" fill="$INK">forgectl</text>
  <text x="58" y="187" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM">content store · tiers</text>

  <rect x="40" y="216" width="250" height="62" rx="4" fill="$PANEL" stroke="$DIM" stroke-width="1"/>
  <text x="58" y="243" font-family="DejaVu Sans Mono" font-size="14" fill="$INK">warden</text>
  <text x="58" y="263" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM">seals · ratchets · revokes</text>

  <!-- ── the cell ─────────────────────────────────────── -->
  <g opacity="$cell_op">
    <text x="470" y="126" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM" letter-spacing="2">CELL — hardware-isolated microVM</text>
    <rect x="470" y="140" width="390" height="200" rx="6" fill="none" stroke="$ACCENT" stroke-width="1.5"/>

    <rect x="492" y="252" width="346" height="62" rx="4" fill="$PANEL" stroke="$DIM" stroke-width="1"/>
    <text x="510" y="279" font-family="DejaVu Sans Mono" font-size="14" fill="$INK">pilot</text>
    <text x="510" y="299" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM">exec-by-hash · lanes · explain</text>

    <!-- agent-authored code, which is the thing to be suspicious of -->
    <g opacity="$agent_op">
      <rect x="492" y="180" width="150" height="46" rx="4" fill="$PANEL" stroke="$WARN" stroke-width="1" stroke-dasharray="3 3"/>
      <text x="508" y="200" font-family="DejaVu Sans Mono" font-size="12" fill="$WARN">agent wrote this</text>
      <text x="508" y="217" font-family="DejaVu Sans Mono" font-size="11" fill="$DIM">never attested</text>
    </g>
  </g>

  <!-- ── the lent tool, in flight then seated ─────────── -->
  <g opacity="$tool_op" transform="translate($tool_x,0)">
    <g opacity="$revoke_op">
      <rect x="0" y="160" width="152" height="46" rx="4" fill="$PANEL" stroke="$seal_stroke" stroke-width="$seal_w"/>
      <text x="16" y="180" font-family="DejaVu Sans Mono" font-size="12.5" fill="$INK">/usr/bin/python</text>
      <text x="16" y="197" font-family="DejaVu Sans Mono" font-size="11" fill="$DIM">$tool_sub</text>
    </g>
  </g>

  <!-- refused write: the assertion the whole design turns on -->
  <g opacity="$strike_op">
    <line x1="648" y1="206" x2="682" y2="188" stroke="$WARN" stroke-width="1.5" stroke-dasharray="4 3"/>
    <text x="560" y="246" font-family="DejaVu Sans Mono" font-size="12" fill="$WARN">write refused below the guest</text>
  </g>

  <!-- lane badge -->
  <g opacity="$([ -n "$lane_text" ] && echo 1 || echo 0)">
    <rect x="668" y="212" width="152" height="24" rx="3" fill="none" stroke="$lane_fill" stroke-width="1"/>
    <text x="680" y="228" font-family="DejaVu Sans Mono" font-size="11" fill="$lane_fill">$lane_text</text>
  </g>

  <!-- ── caption ──────────────────────────────────────── -->
  <line x1="40" y1="368" x2="860" y2="368" stroke="$PANEL" stroke-width="1"/>
  <text x="40" y="396" font-family="DejaVu Sans Mono" font-size="13" fill="$ACCENT">$beat</text>
  <text x="118" y="396" font-family="DejaVu Sans Mono" font-size="13" fill="$INK">$caption</text>
</svg>
SVG
}

i=0
add() { frame "$i" "$@"; i=$((i+1)); }

# hold(n) repeats the previous frame so a step can be read before the next.
hold() { local n="$1"; shift; local k; for ((k=0;k<n;k++)); do add "$@"; done; }

#      cell tool_x t_op seal agent strike revoke lane  caption                                     beat
hold 6  0.15 60   0    0    0     0      1      ""    "a cell is a fork of an already-booted mote" "1"
hold 8  1    60   0    0    0     0      1      ""    "sealed from intent — no boot in the hot path" "1"

# the tool travels from the store into the cell
for x in 60 160 260 360 460 530 590 640 668; do
  add 1 "$x" 1 0 0 0 1 "" "lent as a page map, not a download" "2"
done
hold 8  1    668  1    0    0     0      1      ""    "lent as a page map, not a download"          "2"

hold 10 1    668  1    1    0     0      1      ""    "sealed read-only — below the guest kernel"   "3"

hold 4  1    668  1    1    0.4   0      1      ""    "the agent writes its own code"               "4"
hold 8  1    668  1    1    1     0      1      tool  "the agent writes its own code"               "4"
hold 10 1    668  1    1    1     0      1      data  "an interpreter fed it is demoted, per call"  "4"

hold 4  1    668  1    1    1     0.5    1      data  "so it tries to rewrite the tool instead"     "5"
hold 12 1    668  1    1    1     1      1      data  "refused — not by policy, by the hardware"    "5"

for o in 0.8 0.6 0.4 0.2 0.05; do
  add 1 668 1 1 1 0 "$o" "" "revoked — and it stops in a running cell" "6"
done
hold 12 1    668  1    1    0     0      0      ""    "revoked — and it stops in a running cell"    "6"

printf 'frames:  %s\n' "$i"

for f in "$work"/f*.svg; do
  rsvg-convert -w "$W" -h "$H" "$f" -o "${f%.svg}.png"
done

# One shared palette across every frame: flat colours stay exact and the file
# stays small. Per-frame palettes would dither the cream and shimmer.
ffmpeg -y -loglevel error -framerate 10 -i "$work/f%03d.png" \
  -vf "palettegen=max_colors=32:stats_mode=full" "$work/pal.png"
ffmpeg -y -loglevel error -framerate 10 -i "$work/f%03d.png" -i "$work/pal.png" \
  -lavfi "paletteuse=dither=none" -loop 0 "$out/stack.gif"

# The still is the frame where the story has landed: sealed, demoted, refused.
cp "$work/f072.png" "$out/stack.png"

printf 'gif:     %s (%s)\n' "$out/stack.gif" "$(du -h "$out/stack.gif" | cut -f1)"
printf 'png:     %s (%s)\n' "$out/stack.png" "$(du -h "$out/stack.png" | cut -f1)"
