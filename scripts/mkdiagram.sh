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
# The animation tells a story because a static box diagram of a host and a
# guest looks like every other box diagram. What is worth showing is the
# *movement*: two closures lent, sealed, a model's program run by an attested
# interpreter, the answer coming back, and the lend taken back.
#
# It follows the happy path deliberately. What the hardware refuses is a claim
# worth making, but not in the picture that has to explain what Celln is for -
# a first diagram should show the thing working. The output shown is what the
# README's opening example actually prints.
#
# Note there is no forge in this picture. `celln agent --tool python` asks a
# model for Python and hands it to a lent interpreter — nothing is compiled, so
# nothing is forged. Forging is the other path, for generated Rust.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/docs/assets"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v rsvg-convert >/dev/null || { echo "need rsvg-convert (librsvg)" >&2; exit 1; }
command -v ffmpeg       >/dev/null || { echo "need ffmpeg" >&2; exit 1; }
mkdir -p "$out"

W=940; H=470
BG="#fbfcf9"
PANEL="#ffffff"
INK="#17221e"
DIM="#5c675f"
ACCENT="#165a47"
WARN="#b44a32"
OK="#7fa650"

# frame(index, cell_op, dx, tool_op, sealed, agent_op, out_op, revoke_op,
#       lane, caption, beat)
#
# `dx` slides both closures in from the host together: they are lent by the
# same act. Discrete states with a few tween frames between them — a stack
# diagram reads better as deliberate steps than as constant motion.
frame() {
  local i="$1" cell_op="$2" dx="$3" tool_op="$4" sealed="$5" agent_op="$6" \
        out_op="$7" revoke_op="$8" lane="$9" caption="${10}" beat="${11}"

  local seal_stroke="$DIM" seal_w=1 seal_note="verified"
  if [ "$sealed" = "1" ]; then
    seal_stroke="$ACCENT"; seal_w=2; seal_note="verified · r-x"
  fi

  local lane_fill="$DIM" lane_text=""
  case "$lane" in
    tool) lane_fill="$OK";   lane_text="tool lane" ;;
    data) lane_fill="$WARN"; lane_text="agent lane · demoted" ;;
  esac

  cat > "$work/f$(printf '%03d' "$i").svg" <<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="$W" height="$H" viewBox="0 0 $W $H">
  <rect width="$W" height="$H" fill="$BG"/>

  <!-- wordmark -->
  <text x="40" y="52" font-family="DejaVu Sans Mono" font-size="21" fill="$INK" letter-spacing="1.5">celln</text>
  <text x="40" y="74" font-family="DejaVu Sans Mono" font-size="12.5" fill="$DIM">every tool is memory the host lends in — and can take back</text>

  <!-- ── host ─────────────────────────────────────────── -->
  <text x="40" y="128" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM" letter-spacing="2">HOST</text>
  <rect x="40" y="144" width="262" height="64" rx="4" fill="$PANEL" stroke="$DIM" stroke-width="1"/>
  <text x="58" y="172" font-family="DejaVu Sans Mono" font-size="14" fill="$INK">catalogue</text>
  <text x="58" y="192" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM">digest-pinned tool images</text>

  <path d="M171 208 L171 220" stroke="$DIM" stroke-width="1"/>
  <path d="M167 216 L171 223 L175 216" fill="none" stroke="$DIM" stroke-width="1"/>
  <text x="184" y="221" font-family="DejaVu Sans Mono" font-size="10" fill="$DIM">the whole closure</text>

  <rect x="40" y="224" width="262" height="64" rx="4" fill="$PANEL" stroke="$DIM" stroke-width="1"/>
  <text x="58" y="252" font-family="DejaVu Sans Mono" font-size="14" fill="$INK">assay</text>
  <text x="58" y="272" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM">hashes · grades · attests</text>

  <path d="M171 288 L171 300" stroke="$DIM" stroke-width="1"/>
  <path d="M167 296 L171 303 L175 296" fill="none" stroke="$DIM" stroke-width="1"/>
  <text x="184" y="301" font-family="DejaVu Sans Mono" font-size="10" fill="$DIM">attested bytes</text>

  <rect x="40" y="304" width="262" height="64" rx="4" fill="$PANEL" stroke="$DIM" stroke-width="1"/>
  <text x="58" y="332" font-family="DejaVu Sans Mono" font-size="14" fill="$INK">warden</text>
  <text x="58" y="352" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM">seals · ratchets · revokes</text>

  <!-- ── the cell ─────────────────────────────────────── -->
  <g opacity="$cell_op">
    <text x="470" y="128" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM" letter-spacing="2">CELL — hardware-isolated microVM</text>
    <rect x="470" y="144" width="430" height="248" rx="6" fill="none" stroke="$ACCENT" stroke-width="1.5"/>

    <rect x="488" y="322" width="394" height="56" rx="4" fill="$PANEL" stroke="$DIM" stroke-width="1"/>
    <text x="506" y="347" font-family="DejaVu Sans Mono" font-size="14" fill="$INK">pilot</text>
    <text x="506" y="366" font-family="DejaVu Sans Mono" font-size="11.5" fill="$DIM">exec-by-hash · lanes · explain</text>

    <!-- the model's program: the thing to be suspicious of -->
    <g opacity="$agent_op">
      <rect x="488" y="248" width="196" height="52" rx="4" fill="$PANEL" stroke="$WARN" stroke-width="1" stroke-dasharray="3 3"/>
      <text x="504" y="270" font-family="DejaVu Sans Mono" font-size="12" fill="$WARN">a model wrote this</text>
      <text x="504" y="288" font-family="DejaVu Sans Mono" font-size="11" fill="$DIM">python, never attested</text>
    </g>
  </g>

  <!-- ── two closures, in flight then seated ──────────── -->
  <g opacity="$tool_op" transform="translate($dx,0)">
    <g opacity="$revoke_op">
      <rect x="488" y="172" width="196" height="58" rx="4" fill="$PANEL" stroke="$seal_stroke" stroke-width="$seal_w"/>
      <text x="504" y="193" font-family="DejaVu Sans Mono" font-size="12.5" fill="$INK">/tools</text>
      <text x="504" y="210" font-family="DejaVu Sans Mono" font-size="10.5" fill="$DIM">python@sha256:229a2c…</text>
      <text x="504" y="224" font-family="DejaVu Sans Mono" font-size="10" fill="$DIM">glibc · $seal_note</text>
    </g>
    <g>
      <rect x="700" y="172" width="182" height="58" rx="4" fill="$PANEL" stroke="$seal_stroke" stroke-width="$seal_w"/>
      <text x="716" y="193" font-family="DejaVu Sans Mono" font-size="12.5" fill="$INK">/tools1</text>
      <text x="716" y="210" font-family="DejaVu Sans Mono" font-size="10.5" fill="$DIM">curl@sha256:7c12af…</text>
      <text x="716" y="224" font-family="DejaVu Sans Mono" font-size="10" fill="$DIM">musl · $seal_note</text>
    </g>
  </g>

  <!-- interpretation: the model's program handed to an attested tool -->
  <g opacity="$([ -n "$lane_text" ] && echo 1 || echo 0)">
    <path d="M586 248 L586 236" stroke="$WARN" stroke-width="1" stroke-dasharray="3 2"/>
    <path d="M582 240 L586 233 L590 240" fill="none" stroke="$WARN" stroke-width="1"/>
    <rect x="700" y="248" width="182" height="26" rx="3" fill="none" stroke="$lane_fill" stroke-width="1"/>
    <text x="712" y="265" font-family="DejaVu Sans Mono" font-size="11" fill="$lane_fill">$lane_text</text>
  </g>

  <!-- the answer. What a reader wants to know is that this produces
       something, so the diagram ends on output rather than on a refusal. -->
  <g opacity="$out_op">
    <text x="504" y="313" font-family="DejaVu Sans Mono" font-size="12" fill="$ACCENT">stdout</text>
    <text x="566" y="313" font-family="DejaVu Sans Mono" font-size="12" fill="$INK">GIF image</text>
  </g>

  <!-- ── caption ──────────────────────────────────────── -->
  <line x1="40" y1="412" x2="900" y2="412" stroke="$PANEL" stroke-width="1"/>
  <text x="40" y="440" font-family="DejaVu Sans Mono" font-size="13" fill="$ACCENT">$beat</text>
  <text x="118" y="440" font-family="DejaVu Sans Mono" font-size="13" fill="$INK">$caption</text>
</svg>
SVG
}

i=0
add() { frame "$i" "$@"; i=$((i+1)); }
hold() { local n="$1"; shift; local k; for ((k=0;k<n;k++)); do add "$@"; done; }

#      cell dx   t_op seal agent out  revoke lane  caption                                          beat
hold 6  0.15 -430 0    0    0     0    1      ""    "a cell is a fork of an already-booted mote"      "1"
hold 8  1    -430 0    0    0     0    1      ""    "sealed from intent — no boot in the hot path"    "1"

# both closures travel from the host into the cell, lent by one act
for x in -430 -350 -270 -190 -120 -70 -34 -12 0; do
  add 1 "$x" 1 0 0 0 1 "" "a tool is its whole closure, not one file" "2"
done
hold 10 1    0    1    0    0     0    1      ""    "two images, each its own sealed mount"           "2"

hold 10 1    0    1    1    0     0    1      ""    "sealed read-only — below the guest kernel"       "3"

hold 4  1    0    1    1    0.4   0    1      ""    "a model writes the program, not the tool"        "4"
hold 8  1    0    1    1    1     0    1      ""    "a model writes the program, not the tool"        "4"

hold 6  1    0    1    1    1     0    1      tool  "attested python is asked to run it"              "5"
hold 12 1    0    1    1    1     0    1      data  "so this call is demoted — the laundering ban"    "5"

hold 4  1    0    1    1    1     0.5  1      data  "it runs, with less authority than the tool has"  "6"
hold 14 1    0    1    1    1     1    1      data  "it runs, with less authority than the tool has"  "6"

for o in 0.8 0.6 0.4 0.2 0.05; do
  add 1 0 1 1 1 1 "$o" "" "the lend is taken back; the cell dissolves" "7"
done
hold 12 1    0    1    1    1     1    0      ""    "the lend is taken back; the cell dissolves"      "7"

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

# The still shows the program having run in the agent lane, with its output:
# the whole point, in one frame.
still=$(printf 'f%03d.png' $((i - 18)))
cp "$work/$still" "$out/stack.png"

printf 'gif:     %s (%s)\n' "$out/stack.gif" "$(du -h "$out/stack.gif" | cut -f1)"
printf 'png:     %s (%s)\n' "$out/stack.png" "$(du -h "$out/stack.png" | cut -f1)"
