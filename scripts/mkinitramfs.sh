#!/usr/bin/env bash
# mkinitramfs.sh — build the guest initramfs for boot testing.
#
# Compiles guest/init/init.c freestanding (no libc, raw syscalls) and packs it
# as an uncompressed newc cpio the kernel can unpack as its rootfs. Deliberately
# tiny and dependency-free: the point is a guest userspace we fully control, so
# guest-side claims are proven by guest code, not asserted from the host.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$root/target/nous-initramfs.cpio}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

command -v gcc >/dev/null 2>&1 || { echo "gcc not found — needed to build the guest init" >&2; exit 1; }
command -v cpio >/dev/null 2>&1 || { echo "cpio not found — needed to pack the initramfs" >&2; exit 1; }

# The kernel we boot must be one whose modules are installed, because the DAX
# probe loads nvdimm modules and vermagic is checked exactly. Same rule as
# BootConfig::host_kernel in crates/celln-warden/src/vmm/boot.rs — keep them in step.
pick_kver() {
  local k v
  for k in $(ls -1 /boot/vmlinuz-* 2>/dev/null | grep -v rescue | sort -r); do
    v="${k#/boot/vmlinuz-}"
    [ -r "$k" ] && [ -d "/lib/modules/$v" ] && { echo "$v"; return 0; }
  done
  return 1
}
kver="${2:-$(pick_kver || true)}"

gcc -static -nostdlib -nostartfiles -ffreestanding -fno-stack-protector \
    -fno-asynchronous-unwind-tables -Os -Wall -Wextra \
    -o "$work/init" "$root/guest/init/init.c"

# /dev must exist for init to mount devtmpfs onto it. Device nodes themselves
# cannot be created without privilege, which is why init mounts devtmpfs.
mkdir -p "$work/dev" "$work/tools" "$work/modules" "$work/proc" "$work/sys" \
         "$work/nous/tools" "$work/nous/work"

# ---- pilot, and the manifest it enforces ----------------------------------
#
# pilot runs *inside* the cell. Built static against musl so the guest needs
# nothing but this one file: no libc, no loader, no /lib. init hands control to
# it, and it becomes PID 1.
#
# The manifest and the tools are staged together, deliberately: pilot hashes
# the bytes it finds and checks them against the manifest rather than trusting
# that they are what the host said. Three tools, to exercise all three
# outcomes — an attested interpreter (demoted when fed agent-authored input),
# an attested binary (not demoted), and one that is simply not in the manifest.
pilot_dir="${NOUS_PILOT_DIR:-$root/pilot}"
if [ -x "$pilot_dir/celln-pilot" ] && [ -x "$pilot_dir/pilot-fetch" ]; then
  # An installed distribution ships these two static guest binaries. Keeping
  # them out of the host's PATH prevents an installed `celln agent` from needing
  # a checkout or Cargo merely to construct an initramfs.
  cp "$pilot_dir/celln-pilot" "$work/pilot"
  cp "$pilot_dir/pilot-fetch" "$work/pilot-fetch"
elif rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-musl; then
  ( cd "$root" && cargo build --quiet --release \
      --target x86_64-unknown-linux-musl -p celln-pilot --bin celln-pilot --bin pilot-fetch )
  cp "$root/target/x86_64-unknown-linux-musl/release/celln-pilot" "$work/pilot"
  cp "$root/target/x86_64-unknown-linux-musl/release/pilot-fetch" "$work/pilot-fetch"
else
  printf 'pilot:    skipped (install a distribution with guest assets, or run rustup target add x86_64-unknown-linux-musl)\n'
fi

if [ -x "$work/pilot" ]; then
  printf '#!/attested/python\nprint("attested interpreter")\n' > "$work/nous/tools/python"
  printf 'attested binary bytes, not an interpreter\n'          > "$work/nous/tools/ls"
  printf 'code the agent wrote, never attested\n'               > "$work/nous/tools/agent-script"

  # A caller that has already attested its own artifacts hands us the manifest
  # and the run request, and we only pack them. Attestation is not a packaging
  # step: doing it here would mean `celln agent` needed a cargo toolchain and a
  # source tree at run time, which is not something an installed binary has.
  if [ -n "${NOUS_MANIFEST:-}" ]; then
    cp "$NOUS_MANIFEST" "$work/nous/manifest.json"
    [ -n "${NOUS_RUN_JSON:-}" ] && cp "$NOUS_RUN_JSON" "$work/nous/run.json"
    # The demo tools below belong to the demo, not to a real agent cell.
    rm -f "$work/nous/tools/python" "$work/nous/tools/ls" "$work/nous/tools/agent-script"
    printf 'manifest: supplied by caller (%s entr%s)\n' \
      "$(grep -c '"alias"' "$work/nous/manifest.json")" \
      "$([ "$(grep -c '"alias"' "$work/nous/manifest.json")" = 1 ] && echo y || echo ies)"
    packed_manifest=1
  fi

  store="$(mktemp -d)"
  if [ -z "${packed_manifest:-}" ]; then
  ( cd "$root" && cargo run --quiet -p assay -- --root "$store" \
      admit /usr/bin/python "$work/nous/tools/python" --interpreter >/dev/null )
  ( cd "$root" && cargo run --quiet -p assay -- --root "$store" \
      admit /usr/bin/ls "$work/nous/tools/ls" >/dev/null )
  # `agent-script` is deliberately NOT preforged: pilot must refuse it.

  # A program for the cell to actually run, if one was staged. It is attested
  # here on the host and sealed into the tool filesystem separately, so the
  # only thing crossing into the cell is bytes plus a hash to check them
  # against — pilot re-hashes whatever it finds at that path before running it.
  if [ -n "${NOUS_RUN_PROG:-}" ]; then
    prog_alias="${NOUS_RUN_ALIAS:-/$(basename "$NOUS_RUN_PROG")}"
    # Agent-authored source stays agent-authored through the compiler. Forging
    # it is fine and gives a reproducible artifact; granting it the tool lane
    # is not, so the author rides into the manifest with the hash.
    ( cd "$root" && cargo run --quiet -p assay -- --root "$store" \
        admit "$prog_alias" "$NOUS_RUN_PROG" \
        ${NOUS_RUN_AGENT_AUTHORED:+--agent-authored} >/dev/null )

    args_json="[]"
    if [ -n "${NOUS_RUN_ARGS:-}" ]; then
      args_json="["; sep=""
      for a in $NOUS_RUN_ARGS; do args_json="$args_json$sep\"$a\""; sep=","; done
      args_json="$args_json]"
    fi
    cat > "$work/nous/run.json" <<JSON
{
  "path": "/tools/$(basename "$NOUS_RUN_PROG")",
  "alias": "$prog_alias",
  "args": $args_json,
  "agent_authored_input": ${NOUS_RUN_TAINTED:-false}
}
JSON
    printf 'run:      %s (sealed at /tools/%s)\n' \
      "$prog_alias" "$(basename "$NOUS_RUN_PROG")"
  fi

  cp "$store/manifest.json" "$work/nous/manifest.json"
  fi
  rm -rf "$store"
  printf 'pilot:    staged (static musl) with a %s-entry manifest\n' \
    "$(grep -o '"alias"' "$work/nous/manifest.json" | wc -l)"
fi

# Stage the nvdimm modules the DAX probe needs. They ship xz-compressed;
# decompress here so the guest init can finit_module() them directly instead of
# carrying a decompressor. Missing modules are not fatal — the guest reports
# that the DAX path is unavailable and the /dev/mem probe still runs.
if [ -n "${kver:-}" ]; then
  staged=0
  for m in libnvdimm nd_pmem nd_e820 ramdax; do
    src=$(find "/lib/modules/$kver/kernel/drivers/nvdimm" -name "$m.ko*" 2>/dev/null | head -1)
    [ -n "$src" ] || continue
    case "$src" in
      *.xz)  command -v xz   >/dev/null 2>&1 && xz   -dc "$src" > "$work/modules/$m.ko" && staged=$((staged+1)) ;;
      *.zst) command -v zstd >/dev/null 2>&1 && zstd -dcq "$src" > "$work/modules/$m.ko" && staged=$((staged+1)) ;;
      *.ko)  cp "$src" "$work/modules/$m.ko" && staged=$((staged+1)) ;;
    esac
  done
  printf 'modules:  %s staged for kernel %s\n' "$staged" "$kver"
else
  printf 'modules:  none staged (no /boot kernel with matching /lib/modules)\n'
fi

mkdir -p "$(dirname "$out")"
( cd "$work" && find . -print0 | cpio --null -o -H newc --quiet ) > "$out"

printf 'initramfs: %s (%s bytes, init %s bytes)\n' \
  "$out" "$(stat -c%s "$out")" "$(stat -c%s "$work/init")"
