#!/usr/bin/env bash
# doctor.sh — is this host ready for the real (KVM) Celln path?
# The POC's mock backend runs anywhere; this checks the bare-metal prerequisites
# for M1/M2 (see CELLN_BUILD_PLAN.md §2).
set -euo pipefail

pass() { printf '  \033[32m✔\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m�’\033[0m %s\n' "$1"; }

echo "Celln host doctor"
rc=0

# --- KVM ---
if [ -e /dev/kvm ]; then
  pass "/dev/kvm present"
else
  warn "/dev/kvm absent — mock backend only (fine for POC; real fork needs bare metal)"
fi

# --- virtualization extensions ---
if grep -Eq '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then
  pass "CPU virtualization extensions present (vmx/svm)"
else
  warn "no vmx/svm in /proc/cpuinfo — nested-off cloud VM or unsupported CPU"
fi

# --- kernel version >= 6.12 (Landlock ABI v4+, memslot maturity) ---
kver=$(uname -r | cut -d- -f1)
kmaj=$(echo "$kver" | cut -d. -f1)
kmin=$(echo "$kver" | cut -d. -f2)
if [ "$kmaj" -gt 6 ] || { [ "$kmaj" -eq 6 ] && [ "$kmin" -ge 12 ]; }; then
  pass "kernel $kver (>= 6.12)"
else
  warn "kernel $kver (< 6.12) — Landlock network rules / memslot maturity may be missing"
fi

# --- rust toolchain ---
if command -v cargo >/dev/null 2>&1; then
  pass "cargo present ($(cargo --version | awk '{print $2}'))"
else
  fail "cargo not found — install Rust to build"
  rc=1
fi

# --- stock-kernel boot testing (make boot-kvm) ---
kernel=$(ls -1 /boot/vmlinuz-* 2>/dev/null | grep -v rescue | tail -1 || true)
if [ -n "$kernel" ] && [ -r "$kernel" ]; then
  pass "bootable kernel image readable ($(basename "$kernel"))"
else
  warn "no readable /boot/vmlinuz-* — boot tests will skip"
fi

missing=""
for t in gcc cpio mke2fs; do
  command -v "$t" >/dev/null 2>&1 || missing="$missing $t"
done
if [ -z "$missing" ]; then
  pass "guest image toolchain present (gcc, cpio, e2fsprogs)"
else
  warn "missing:$missing — guest images cannot be built, boot tests will skip"
fi

echo
if [ "$rc" -eq 0 ]; then
  if [ -e /dev/kvm ]; then
    echo "Ready to build. Run: make demo-kvm (real hardware) or make demo (mock)"
  else
    echo "Ready to build. Run: make demo"
  fi
else
  echo "Missing prerequisites above."
fi
exit "$rc"
