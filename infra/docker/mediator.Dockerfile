# syntax=docker/dockerfile:1
#
# DIDComm/TSP mediator for the local research stack.
#
# Build context: infra/vendor/mediator (a vendored snapshot of
# affinidi-messaging-mediator, see infra/PROVENANCE.md). Derived from the
# upstream docker/mediator.Dockerfile, minus the AWS secret/publish backends
# (the stack uses the plain file:// secret store) and with BuildKit cache
# mounts instead of cargo-chef.
#
# Binaries: /usr/local/bin/mediator, /usr/local/bin/mediator-setup.
# Runs as UID 10001. Base images are pinned by digest (same digests upstream).

FROM rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS builder
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends \
        build-essential pkg-config libdbus-1-dev libssl-dev \
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
# mediator: its default features (didcomm, tsp, redis-backend, jemalloc, vta).
# mediator-setup: only the `vta` flows; the file:// secret store needs no feature.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target,id=openvtc-research-mediator-target \
    cargo build --release --locked \
        -p affinidi-messaging-mediator -p affinidi-messaging-mediator-setup \
        --no-default-features \
        --features affinidi-messaging-mediator/default,affinidi-messaging-mediator-setup/vta \
    && mkdir -p /out \
    && cp target/release/mediator target/release/mediator-setup /out/

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends ca-certificates libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 mediator \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin mediator \
    && mkdir -p /etc/mediator/conf && chown -R 10001:10001 /etc/mediator
WORKDIR /etc/mediator
COPY --from=builder /out/mediator /out/mediator-setup /usr/local/bin/
USER 10001:10001
EXPOSE 7037
ENTRYPOINT ["/usr/local/bin/mediator"]
