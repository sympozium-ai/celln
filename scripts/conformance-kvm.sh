#!/usr/bin/env bash
# Explicit hardware tier: prepare every fixture; never accept printed skips.
set -euo pipefail
umask 077
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo 'KVM is required for conformance' >&2; exit 1; }
for tool in gcc cpio mke2fs rustc; do command -v "$tool" >/dev/null || { echo "missing conformance tool: $tool" >&2; exit 1; }; done
pilot_dir="$root/target/x86_64-unknown-linux-musl/release"
# This target performs no billable model smoke or arbitrary external hooks.
unset CELLN_MODEL_TOKEN_FILE CELLN_HARNESS_CONTROLLER_HOOK CELLN_SYMPOZIUM_PROOF CELLN_PILOT_DIR
out="$(mktemp -d "$root/target/conformance-kvm.XXXXXXXX")"
CELLN_PILOT_DIR="$pilot_dir" "${CARGO:-cargo}" run --locked --quiet -p celln-pilot --features kvm --bin celln-json-harness-proof -- --package-only > "$out/package.log" 2>&1
package="$(awk -F'; ' '/^PACKAGED: native JSON Harness/{print $NF}' "$out/package.log")"
[[ -d "$package" && -f "$package/signed-closure.json" ]] || { echo "missing generated JSON package; inspect $out/package.log" >&2; exit 1; }
export CELLN_HARNESS_PACKAGE="$package"
result=0
echo "KVM conformance logs: $out"
# Separate test processes prevent one failed proof's poisoned global lock from
# hiding the outcomes of every remaining proof. All required cases still run.
for test in signed_closure_on_real_kvm declared_parent_launcher_on_real_kvm declared_substrate_on_real_kvm dispatch_outcomes_on_real_kvm json_harness_grant_issuance_on_real_kvm json_direct_adapter_on_real_kvm; do
  code=0
  "${CARGO:-cargo}" test --locked -p celln-cli --bin celln "$test" -- --ignored --nocapture --test-threads=1 > "$out/$test.log" 2>&1 || code=$?
  if grep -Eiq '(^|[[:space:]])skip(ping)?:' "$out/$test.log" || ! grep -q '1 passed; 0 failed' "$out/$test.log"; then code=1; fi
  printf '%s\t%s\n' "$test" "$code" >> "$out/results.tsv"
  if [[ "$code" != 0 ]]; then echo "KVM case incomplete/failed: $test" >&2; result=1; fi
done
exit "$result"
