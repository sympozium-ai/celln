# Celln router image.
#
# Used by the celln-router Deployment. The router forwards HTTP requests
# to the host-level dispatcher (systemd service). It does not run celln
# agent itself — the dispatcher handles forge/assay/KVM on the host.
#
# Includes curl + python3 for the deepseek-api script, and Rust
# for debugging (optional — the forge step runs on the host).
#
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates python3 \
    build-essential gcc cpio e2fsprogs xz-utils zstd \
    && rm -rf /var/lib/apt/lists/*
RUN curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH=/root/.cargo/bin:/usr/local/bin:/opt/celln/runtime/scripts:/usr/bin:/bin:/sbin:/usr/sbin
RUN rustup target add x86_64-unknown-linux-musl
RUN mkdir -p /opt/celln/runtime /var/lib/celln
ENTRYPOINT ["/usr/local/bin/celln"]
