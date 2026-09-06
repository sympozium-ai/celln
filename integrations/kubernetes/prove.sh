#!/usr/bin/env bash
# Refreshed from muddlebee's PR #25: isolated kubeconfig, unique evidence,
# Docker/Podman providers, and no mutation of any pre-existing cluster.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${CELLN_KUBERNETES_PROOF_DIR:-$root/target/kubernetes-proof}"
cluster="${CELLN_KIND_CLUSTER:-celln-conformance-$$}"
kind_bin="${CELLN_KIND_BIN:-kind}"
provider="${KIND_EXPERIMENTAL_PROVIDER:-}"
if [[ -z "$provider" ]]; then
  if command -v docker >/dev/null; then provider=docker; else provider=podman; fi
fi
[[ "$provider" == docker || "$provider" == podman ]] || { echo 'provider must be docker or podman' >&2; exit 1; }
[[ "$cluster" =~ ^celln-conformance-[a-z0-9-]+$ ]] || { echo 'use a unique celln-conformance-* cluster name' >&2; exit 1; }
for tool in cargo jq rg kubectl "$kind_bin" "$provider"; do
  command -v "$tool" >/dev/null || { echo "missing prerequisite: $tool" >&2; exit 1; }
done
[[ "$(uname -m)" == x86_64 ]] || { echo 'requires x86_64' >&2; exit 1; }
"$provider" info >/dev/null
export KIND_EXPERIMENTAL_PROVIDER="$provider"
clusters="$("$kind_bin" get clusters)"
if rg -Fxq "$cluster" <<< "$clusters"; then
  echo "refusing to reuse existing cluster: $cluster" >&2; exit 1
fi
work="$(mktemp -d /tmp/celln-conformance.XXXXXX)"
export KUBECONFIG="$work/kubeconfig"
created=false
cleanup() {
  if [[ "$created" == true && "${KEEP_CLUSTER:-0}" != 1 ]]; then
    "$kind_bin" delete cluster --name "$cluster" >/dev/null 2>&1 || true
  fi
  [[ "$work" == /tmp/celln-conformance.* && -d "$work" ]] && rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$out"
evidence="$(mktemp -d "$out/run.XXXXXX")"
image="localhost/celln-conformance:$$"
(
  cd "$root"
  cargo build --release --locked --target x86_64-unknown-linux-musl -p celln-cli
)
binary="$root/target/x86_64-unknown-linux-musl/release/celln"
cp "$binary" "$work/celln"
"$provider" build --tag "$image" --file "$root/integrations/kubernetes/Dockerfile" "$work"
"$provider" save --output "$work/image.tar" "$image"
created=true
"$kind_bin" create cluster --name "$cluster" --wait 120s
"$kind_bin" load image-archive "$work/image.tar" --name "$cluster"
sed "s|celln-node:dev|$image|" "$root/integrations/kubernetes/conformance/unsupported-hardware.yaml" |
  kubectl --context "kind-$cluster" apply -f -
if ! kubectl --context "kind-$cluster" -n celln-system wait --for=condition=complete job/celln-conformance-unsupported --timeout=120s; then
  kubectl --context "kind-$cluster" -n celln-system describe job/celln-conformance-unsupported >&2 || true
  kubectl --context "kind-$cluster" -n celln-system logs job/celln-conformance-unsupported >&2 || true
  exit 1
fi
kubectl --context "kind-$cluster" -n celln-system logs job/celln-conformance-unsupported | tee "$evidence/unsupported-hardware.json"
jq -e '.verdict == "refused" and .reason == "unsupported" and .request_id == "celln-conformance-unsupported" and .node.kvm == false' "$evidence/unsupported-hardware.json" >/dev/null
jq -n --slurpfile result "$evidence/unsupported-hardware.json" \
  --arg revision "$(git -C "$root" rev-parse HEAD)" --arg provider "$provider" \
  --arg binary "$(sha256sum "$binary" | cut -d ' ' -f 1)" \
  --arg kind "$("$kind_bin" version)" --arg runtime "$("$provider" --version)" \
  --arg dirty "$(git -C "$root" status --porcelain)" \
  '{suite:"celln-kubernetes-conformance",status:"passed",revision:$revision,dirty:($dirty != ""),provider:$provider,kind:$kind,runtime:$runtime,binarySha256:$binary,cases:[{name:"unsupported_hardware",status:"passed",evidence:$result[0]}]}' > "$evidence/summary.json"
echo "PASS: Kubernetes unsupported-hardware preflight; evidence $evidence"
