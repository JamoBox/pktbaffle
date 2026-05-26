# ── Build environment for the pktbaffle workspace ────────────────────────────
#
# The source tree is mounted as a volume at /workspace so changes on the host
# are visible immediately without rebuilding the image.  The image pre-fetches
# all workspace dependencies so the first `cargo test` doesn't hit the network.
#
# Build:  docker compose build
# Use:    docker compose run --rm test
#         docker compose run --rm live-test
#         docker compose run --rm dev

FROM rust:slim-bookworm

# System packages needed for building and network testing.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        netcat-openbsd \
        tcpdump \
        libcap2-bin \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

ENV CARGO_HOME=/cargo-cache
ENV RUST_BACKTRACE=1

WORKDIR /workspace

# Pre-fetch all workspace dependencies into the cargo cache.
# Only manifests and the lock file are copied — this layer is only invalidated
# when dependencies change, not when source files change.
COPY Cargo.toml Cargo.lock ./
COPY pktbaffle/Cargo.toml pktbaffle/Cargo.toml
COPY pkttap/Cargo.toml pkttap/Cargo.toml

# Stub out the minimum source structure Cargo needs to resolve the workspace,
# then fetch all dependencies. The real source is mounted at runtime.
RUN mkdir -p pktbaffle/src pkttap/src \
    && echo > pktbaffle/src/lib.rs \
    && echo > pkttap/src/lib.rs \
    && cargo fetch \
    && rm -rf pktbaffle pkttap

# The source tree is mounted here at runtime (see docker-compose.yml volumes).
# CARGO_HOME lives in a named Docker volume so the registry and compiled
# artifacts survive container restarts without re-downloading.
CMD ["cargo", "test", "--workspace"]
