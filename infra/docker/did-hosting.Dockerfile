# syntax=docker/dockerfile:1
#
# did:webvh hosting (did-hosting-daemon: control plane + public resolver +
# witness in one process) for the local research stack.
#
# Build context: infra/vendor/did-hosting (a vendored snapshot of
# affinidi-webvh-service, see infra/PROVENANCE.md).
#
# Features: fjall store, did:webvh + did:web resolution, jemalloc. No admin UI
# (no Node toolchain needed), no OS keyring (containers have none; the stack
# uses the plaintext secret backend).

FROM rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS builder
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends \
        build-essential pkg-config libdbus-1-dev libssl-dev clang cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Parallel rustc jobs. Docker Desktop's default VM (~8 GiB) runs out of memory
# with one job per core; raise this on a bigger build host.
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
# Infrastructure only (not under study): trade a little runtime speed for a
# much cheaper build than the upstream release profile (fat/thin LTO, 1 CGU).
ENV CARGO_PROFILE_RELEASE_LTO=off \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,id=openvtc-research-did-hosting-target \
    cargo build --release --locked -p did-hosting-daemon \
        --no-default-features --features store-fjall,did-methods,jemalloc \
    && mkdir -p /out && cp target/release/did-hosting-daemon /out/

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends ca-certificates libdbus-1-3 wget \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10002 --system --home-dir /var/lib/did-hosting --create-home --shell /usr/sbin/nologin didhost
COPY --from=builder /out/did-hosting-daemon /usr/local/bin/did-hosting-daemon
USER didhost
WORKDIR /var/lib/did-hosting
EXPOSE 8534
ENTRYPOINT ["/usr/local/bin/did-hosting-daemon"]
