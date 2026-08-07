#!/usr/bin/env bash
# setup-host.sh — Install Celln dispatcher on a KVM-capable node.
#
# Runs either directly on the host (sudo bash setup-host.sh) or inside a
# privileged container (DaemonSet) that mounts the host filesystem at /host.
# When running in a container, files are copied to /host/usr/local/bin etc.
#
# Idempotent: if celln is already installed, just verifies the service is
# running and exits (or sleeps in container mode).
set -euo pipefail

CONTAINER_MODE=false
HOST=""
if [ -d /host/usr ] && [ -f /host/etc/os-release ]; then
    CONTAINER_MODE=true
    HOST="/host"
    echo "→ running in container mode, host at $HOST"
else
    echo "→ running in host mode"
fi

# ── 1. Check if already installed ─────────────────────────────────────
ALREADY_INSTALLED=false
if $CONTAINER_MODE; then
    if [ -x "${HOST}/usr/local/bin/celln" ] && nsenter --target 1 --mount -- systemctl is-active --quiet celln-dispatcher 2>/dev/null; then
        ALREADY_INSTALLED=true
    fi
else
    if [ -x "${HOST}/usr/local/bin/celln" ] && systemctl is-active --quiet celln-dispatcher 2>/dev/null; then
        ALREADY_INSTALLED=true
    fi
fi

if $ALREADY_INSTALLED; then
    echo "✓ celln dispatcher already installed and running"
    if $CONTAINER_MODE; then
        echo "  sleeping (installer DaemonSet health check)..."
        exec sleep infinity
    fi
    exit 0
fi

# ── 2. Copy celln binary ──────────────────────────────────────────────
mkdir -p "${HOST}/usr/local/bin"
# Stop existing dispatcher briefly to replace the binary
if $CONTAINER_MODE; then
    nsenter --target 1 --mount -- systemctl stop celln-dispatcher 2>/dev/null || true
else
    systemctl stop celln-dispatcher 2>/dev/null || true
fi
if [ -f /usr/local/bin/celln ]; then
    cp /usr/local/bin/celln "${HOST}/usr/local/bin/celln"
    chmod 755 "${HOST}/usr/local/bin/celln"
    echo "✓ celln binary installed"
else
    echo "✘ celln binary not found in container — build it first"
    exit 1
fi

# ── 3. Copy runtime assets ─────────────────────────────────────────────
mkdir -p "${HOST}/opt/celln/runtime/"{scripts,pilot,guest/init}
for dir in scripts pilot guest; do
    if [ -d "/opt/celln/runtime/$dir" ]; then
        cp -r "/opt/celln/runtime/$dir"/* "${HOST}/opt/celln/runtime/$dir/" 2>/dev/null || true
    fi
done
echo "✓ runtime assets installed"

# ── 4. State directory ─────────────────────────────────────────────────
mkdir -p "${HOST}/var/lib/celln/"{motes,tools,cells}
echo "✓ state directory created"

# ── 5. Install Rust for root (needed by forge to compile generated code)
if ! [ -x "${HOST}/root/.cargo/bin/rustc" ]; then
    echo "  installing Rust toolchain for root (one-time)..."
    if $CONTAINER_MODE; then
        # In container mode, Rust is already installed in the container.
        # Copy it to the host.
        mkdir -p "${HOST}/root/.cargo/bin"
        cp -r /root/.cargo/* "${HOST}/root/.cargo/" 2>/dev/null || true
        nsenter --target 1 --mount -- /root/.cargo/bin/rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
    else
        curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
        source /root/.cargo/env
        rustup target add x86_64-unknown-linux-musl
    fi
    echo "✓ Rust toolchain installed"
else
    echo "✓ Rust toolchain already present"
fi

# ── 6. API key file ────────────────────────────────────────────────────
if [ -n "${DEEPSEEK_API_KEY:-}" ]; then
    mkdir -p "${HOST}/etc/celln"
    echo "DEEPSEEK_API_KEY=$DEEPSEEK_API_KEY" > "${HOST}/etc/celln/deepseek-key"
    chmod 600 "${HOST}/etc/celln/deepseek-key"
    echo "✓ DeepSeek API key configured"
else
    echo "⚠ DEEPSEEK_API_KEY not set — create /etc/celln/deepseek-key manually"
fi

# ── 7. Dispatcher token ────────────────────────────────────────────────
mkdir -p "${HOST}/etc/celln/dispatcher-token"
if [ ! -f "${HOST}/etc/celln/dispatcher-token/token" ]; then
    openssl rand -base64 32 > "${HOST}/etc/celln/dispatcher-token/token"
    chmod 600 "${HOST}/etc/celln/dispatcher-token/token"
fi
echo "✓ dispatcher token created"

# ── 8. Systemd service ─────────────────────────────────────────────────
cat > "${HOST}/etc/systemd/system/celln-dispatcher.service" << 'UNIT'
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

# SELinux
chcon -t bin_t "${HOST}/usr/local/bin/celln" 2>/dev/null || true

# Reload and start
if $CONTAINER_MODE; then
    nsenter --target 1 --mount -- systemctl daemon-reload
    nsenter --target 1 --mount -- systemctl enable celln-dispatcher
    nsenter --target 1 --mount -- systemctl start celln-dispatcher
    echo "✓ systemd service installed and started (via nsenter)"
else
    systemctl daemon-reload
    systemctl enable --now celln-dispatcher
    echo "✓ systemd service installed and started"
fi

# ── 9. Firewall ────────────────────────────────────────────────────────
if $CONTAINER_MODE; then
    nsenter --target 1 --mount -- firewall-cmd --add-port=8787/tcp --permanent 2>/dev/null || true
    nsenter --target 1 --mount -- firewall-cmd --reload 2>/dev/null || true
else
    firewall-cmd --add-port=8787/tcp --permanent 2>/dev/null || true
    firewall-cmd --reload 2>/dev/null || true
fi
echo "✓ firewall configured"

# ── 10. Environment for users ─────────────────────────────────────────
grep -q "CELLN_ROOT" "${HOST}/etc/environment" 2>/dev/null || \
    echo "CELLN_ROOT=/var/lib/celln" >> "${HOST}/etc/environment"

echo ""
echo "========================================="
echo "  CELLN DISPATCHER INSTALLED"
echo "========================================="

# In container mode, sleep so the DaemonSet stays healthy
if $CONTAINER_MODE; then
    echo "  Installer complete — sleeping (DaemonSet health check)"
    exec sleep infinity
fi
