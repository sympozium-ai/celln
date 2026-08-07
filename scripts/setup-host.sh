# Celln — bare-metal node setup.
#
# Installs celln on a KVM-capable host and configures the systemd service
# so the Celln dispatcher starts on boot and survives restarts.
#
# Run as root:
#   sudo bash setup-host.sh
#
# Pre-requisites (already present on framework):
#   - /dev/kvm
#   - /boot/vmlinuz-*  (guest kernel)
#   - DeepSeek API key in ~/.zshrc or ~/.bashrc (DEEPSEEK_API_KEY=sk-...)
#   - Rust toolchain (curl -sSf https://sh.rustup.rs | sh)
#   - Containerd or Docker (for the celln-node image used by the router)
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'
info()  { echo -e "${GREEN}→${NC} $*"; }
err()   { echo -e "${RED}✘${NC} $*" >&2; exit 1; }

# ── 1. Celln binary ───────────────────────────────────────────────────
info "installing celln binary …"
if ! command -v celln >/dev/null 2>&1; then
    # Build from the repo if it exists, otherwise expect the binary nearby
    if [ -f "$(dirname "$0")/target/release/celln" ]; then
        cp "$(dirname "$0")/target/release/celln" /usr/local/bin/celln
    elif [ -f /home/axjns/bin/celln ]; then
        cp /home/axjns/bin/celln /usr/local/bin/celln
    else
        err "celln binary not found — build it first: cargo build --release --target x86_64-unknown-linux-musl -p celln-cli"
    fi
fi
chmod +x /usr/local/bin/celln
restorecon -v /usr/local/bin/celln 2>/dev/null || true  # SELinux

# ── 2. Runtime assets ─────────────────────────────────────────────────
info "installing runtime assets …"
RUNTIME="${CELLN_RUNTIME_DIR:-/opt/celln/runtime}"
mkdir -p "$RUNTIME"/{scripts,pilot,guest/init}
# Look for assets in the repo checkout or a pre-built location
REPO="${CELLN_REPO:-/home/axjns/Code/celln}"
if [ -d "$REPO/scripts" ]; then
    cp -r "$REPO/scripts"/* "$RUNTIME/scripts/"
    cp -r "$REPO/guest"/*   "$RUNTIME/guest/"
fi
if [ -d "$REPO/target/x86_64-unknown-linux-musl/release" ]; then
    cp "$REPO/target/x86_64-unknown-linux-musl/release/celln-pilot"  "$RUNTIME/pilot/" 2>/dev/null || true
    cp "$REPO/target/x86_64-unknown-linux-musl/release/pilot-fetch" "$RUNTIME/pilot/" 2>/dev/null || true
fi
restorecon -Rv "$RUNTIME" 2>/dev/null || true  # SELinux

# ── 3. State directory ───────────────────────────────────────────────
info "creating state directory …"
mkdir -p /var/lib/celln/{motes,tools,cells}

# ── 4. Rust toolchain (for forge compile step) ────────────────────────
info "checking Rust toolchain …"
if ! sudo -u "${SUDO_USER:-root}" bash -c 'command -v rustc' >/dev/null 2>&1; then
    info "installing Rust for root …"
    curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
    source /root/.cargo/env
    rustup target add x86_64-unknown-linux-musl
fi

# ── 5. API key file ───────────────────────────────────────────────────
info "configuring API key …"
# Source the user's shell profile to pick up DEEPSEEK_API_KEY
USER_HOME=$(eval echo "~${SUDO_USER:-root}")
if [ -f "$USER_HOME/.zshrc" ]; then
    source "$USER_HOME/.zshrc" 2>/dev/null || true
elif [ -f "$USER_HOME/.bashrc" ]; then
    source "$USER_HOME/.bashrc" 2>/dev/null || true
fi
if [ -n "${DEEPSEEK_API_KEY:-}" ]; then
    mkdir -p /etc/celln
    echo "DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY" > /etc/celln/deepseek-key
    chmod 600 /etc/celln/deepseek-key
    info "DeepSeek key configured"
else
    echo "WARNING: DEEPSEEK_API_KEY not found — set it in ~/.zshrc and re-run" >&2
fi

# ── 6. Dispatcher token ───────────────────────────────────────────────
info "generating dispatcher token …"
mkdir -p /etc/celln/dispatcher-token
if [ ! -f /etc/celln/dispatcher-token/token ]; then
    openssl rand -base64 32 > /etc/celln/dispatcher-token/token
    chmod 600 /etc/celln/dispatcher-token/token
fi

# ── 7. Systemd service ────────────────────────────────────────────────
info "installing systemd service …"
cat > /etc/systemd/system/celln-dispatcher.service << 'UNIT'
[Unit]
Description=Celln Dispatcher — hermetic agent actions
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/celln --root /var/lib/celln dispatcher --listen 0.0.0.0:8787 --token-file /etc/celln/dispatcher-token/token
Restart=always
RestartSec=5
Environment=PATH=/root/.cargo/bin:/usr/local/bin:/opt/celln/runtime/scripts:/usr/bin:/bin
Environment=CELLN_RUNTIME_DIR=/opt/celln/runtime
Environment=CELLN_AGENT=deepseek
EnvironmentFile=-/etc/celln/deepseek-key
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now celln-dispatcher

# ── 8. Open firewall ──────────────────────────────────────────────────
info "opening firewall …"
firewall-cmd --add-port=8787/tcp --permanent 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true

# ── 9. Environment for users ─────────────────────────────────────────
info "setting CELLN_ROOT for all users …"
grep -q "CELLN_ROOT" /etc/environment 2>/dev/null || \
    echo "CELLN_ROOT=/var/lib/celln" >> /etc/environment

echo ""
echo "========================================="
echo "  CELLN DISPATCHER INSTALLED"
echo "========================================="
echo ""
echo "  Status:  sudo systemctl status celln-dispatcher"
echo "  Logs:    sudo journalctl -u celln-dispatcher -f"
echo ""
echo "  Verify:  celln doctor"
echo "           curl http://localhost:8787/v1/health"
