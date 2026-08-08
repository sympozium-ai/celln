# Celln router image.
#
# Used by the celln-router DaemonSet. The router forwards HTTP requests
# to the host-level dispatcher (systemd service). It does not run celln
# agent itself — the dispatcher handles forge/assay/KVM on the host.
#
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/celln/runtime /var/lib/celln
ENTRYPOINT ["/usr/local/bin/celln"]
