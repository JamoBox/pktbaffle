# ── Build environment for pktbaffle ──────────────────────────────────────────
#
# Single stage: the source tree is mounted as a volume at /workspace so
# changes on the host are visible immediately without rebuilding the image.
# The image only needs to install Rust, system libs, and network debugging tools.
#
# Build:  docker compose build
# Use:    docker compose run --rm test
#         docker compose run --rm live-test
#         docker compose run --rm dev

FROM rust:1.78-slim-bookworm

# System packages needed for building and network testing.
RUN apt-get update && apt-get install -y --no-install-recommends \
        # BPF / network capability inspection
        iproute2 \
        iputils-ping \
        netcat-openbsd \
        tcpdump \
        libcap2-bin \
        # General dev tools
        curl \
        git \
        && rm -rf /var/lib/apt/lists/*

# Pre-warm the cargo registry by building a throwaway project that pulls in
# the same dev-dependencies we use (libc).  This layer is cached as long as
# the dependency list doesn't change.
RUN cargo new --lib /tmp/_warmup && \
    cat >> /tmp/_warmup/Cargo.toml <<'EOF'
[dev-dependencies]
libc = "0.2"
EOF
RUN cd /tmp/_warmup && cargo test 2>/dev/null || true && \
    rm -rf /tmp/_warmup

WORKDIR /workspace

# The source tree is mounted here at runtime.
# CARGO_HOME is kept inside the named Docker volume (see docker-compose.yml)
# so that the registry and compiled dependencies survive container restarts.
ENV CARGO_HOME=/cargo-cache
ENV RUST_BACKTRACE=1

CMD ["cargo", "test"]
