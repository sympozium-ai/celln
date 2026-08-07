#!/usr/bin/env bash
# install-k8s.sh — Prepare framework for a single-node kubeadm cluster
# with containerd. After this, run setup-host.sh to install the Celln
# host-level dispatcher, and then deploy the router.
#
# Run as root:
#   sudo bash setup-k8s.sh
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
info()  { echo -e "${GREEN}→${NC} $*"; }
err()   { echo -e "${RED}✘${NC} $*" >&2; exit 1; }

# ── 1. Kernel modules + sysctl ───────────────────────────────────────
info "loading kernel modules …"
cat > /etc/modules-load.d/k8s.conf << 'EOF'
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

cat > /etc/sysctl.d/k8s.conf << 'EOF'
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system > /dev/null

# ── 2. Disable swap ───────────────────────────────────────────────────
swapoff -a
sed -i '/swap/d' /etc/fstab

# ── 3. Install containerd ─────────────────────────────────────────────
info "installing containerd …"
dnf install -y containerd
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
# Enable SystemdCgroup for cgroup v2
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl enable --now containerd

# ── 4. Install kubeadm, kubelet, kubectl ──────────────────────────────
info "installing kubeadm …"
cat > /etc/yum.repos.d/kubernetes.repo << 'EOF'
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.35/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.35/rpm/repodata/repomd.xml.key
EOF
dnf install -y kubeadm kubelet kubectl
systemctl enable --now kubelet

# ── 5. Init cluster ───────────────────────────────────────────────────
info "initialising cluster (single-node, pod CIDR 10.244.0.0/16 for flannel) …"
kubeadm init --pod-network-cidr=10.244.0.0/16

# ── 6. Configure kubectl for the axjns user ───────────────────────────
info "configuring kubectl …"
mkdir -p /home/axjns/.kube
cp -f /etc/kubernetes/admin.conf /home/axjns/.kube/config
chown -R axjns:axjns /home/axjns/.kube

# ── 7. Untaint control-plane node so pods can schedule ────────────────
export KUBECONFIG=/etc/kubernetes/admin.conf
kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true

# ── 8. Install Flannel CNI ────────────────────────────────────────────
info "installing flannel …"
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml

info "waiting for node to become ready …"
kubectl wait --for=condition=Ready node --all --timeout=120s

# ── 9. Install Helm ───────────────────────────────────────────────────
info "installing helm …"
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

echo ""
echo "========================================="
echo "  KUBERNETES READY"
echo "========================================="
kubectl get nodes
kubectl get pods -A

# ── 10. Sympozium CRDs ────────────────────────────────────────────────
info "installing Sympozium CRDs …"
kubectl apply -f /home/axjns/Code/sympozium/charts/sympozium-crds/templates/sympozium.ai_agentruns.yaml 2>/dev/null || true

echo ""
echo "Done. Next steps:"
echo ""
echo "  1. Install the host-level Celln dispatcher:"
echo "     sudo bash ~/Code/celln/scripts/setup-host.sh"
echo ""
echo "  2. Deploy Sympozium (Helm):"
echo "     cd ~/Code/sympozium && helm install sympozium ./charts/sympozium \\"
echo "       --namespace sympozium-system --create-namespace \\"
echo "       --set image.registry=ghcr.io/sympozium-ai/sympozium \\"
echo "       --set image.tag=v0.10.43 \\"
echo "       --set image.pullPolicy=IfNotPresent \\"
echo "       --set controller.image.tag=celln-dev \\"
echo "       --set apiserver.image.tag=celln-dev"
echo ""
echo "  3. Deploy the Celln router (Kubernetes Pod):"
echo "     kubectl apply -f ~/Code/celln/integrations/kubernetes/router-deployment.yaml"
echo "     kubectl apply -f ~/Code/celln/integrations/kubernetes/router-service.yaml"
echo ""
echo "  4. Run a demo:"
echo "     kubectl apply -f ~/Code/sympozium/examples/celln-demo.yaml"
