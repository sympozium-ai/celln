#!/usr/bin/env bash
# Run the first Kubernetes execution-plane conformance case.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${CELLN_KUBERNETES_PROOF_DIR:-$root/target/kubernetes-proof}"
cluster="${CELLN_KIND_CLUSTER:-celln-conformance}"
context="kind-$cluster"
image="celln-node:dev"
manifest="$root/integrations/kubernetes/conformance/unsupported-hardware.yaml"
binary="$root/target/x86_64-unknown-linux-musl/release/celln"
image_context="$(mktemp -d "${TMPDIR:-/tmp}/celln-conformance-image.XXXXXX")"
cluster_created=false

cleanup() {
  rm -rf "$image_context"
  if [[ "$cluster_created" == true && "${KEEP_CLUSTER:-0}" != 1 ]]; then
    kind delete cluster --name "$cluster" >/dev/null
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: $1 is required to run the Kubernetes conformance preflight" >&2
    exit 1
  }
}

for tool in cargo docker jq kind kubectl; do
  need "$tool"
done

if [[ "$(uname -m)" != x86_64 ]]; then
  echo "error: the Celln KVM backend and release binary currently require x86_64" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "error: the Docker daemon is unavailable" >&2
  exit 1
fi

clusters="$(kind get clusters 2>/dev/null || true)"
if grep -Fxq "$cluster" <<< "$clusters"; then
  echo "error: Kind cluster '$cluster' already exists; choose CELLN_KIND_CLUSTER or delete it" >&2
  exit 1
fi

mkdir -p "$out"
rm -f "$out/unsupported-hardware.json" "$out/summary.json"

echo "building the static Celln node binary"
(
  cd "$root"
  cargo build --release --locked --target x86_64-unknown-linux-musl -p celln-cli
)
cp "$binary" "$image_context/celln"

echo "building and loading $image"
docker build --tag "$image" --file "$root/integrations/kubernetes/Dockerfile" "$image_context"
kind create cluster --name "$cluster" --wait 120s
cluster_created=true
kind load docker-image "$image" --name "$cluster"

echo "running unsupported-hardware conformance case"
kubectl --context "$context" apply --filename "$manifest" >/dev/null
if ! kubectl --context "$context" wait \
  --namespace celln-system \
  --for=condition=complete \
  job/celln-conformance-unsupported \
  --timeout=120s >/dev/null; then
  kubectl --context "$context" describe \
    --namespace celln-system job/celln-conformance-unsupported >&2 || true
  kubectl --context "$context" logs \
    --namespace celln-system job/celln-conformance-unsupported >&2 || true
  exit 1
fi

raw="$out/unsupported-hardware.json"
kubectl --context "$context" logs \
  --namespace celln-system job/celln-conformance-unsupported | tee "$raw"

jq -e '
  .verdict == "refused" and
  .reason == "unsupported" and
  .request_id == "celln-conformance-unsupported" and
  .node.kvm == false
' "$raw" >/dev/null

jq -n --slurpfile evidence "$raw" '{
  suite: "celln-kubernetes-conformance",
  status: "passed",
  cases: [{
    name: "unsupported_hardware",
    status: "passed",
    evidence: $evidence[0]
  }]
}' > "$out/summary.json"

echo "conformance: unsupported hardware was truthfully refused"
echo "evidence: $out"
