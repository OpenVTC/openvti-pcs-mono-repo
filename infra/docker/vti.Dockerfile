# syntax=docker/dockerfile:1
#
# VTA + VTC (+ the pnm / cnm admin CLIs) for the local research stack, built
# from the research repo's ROOT cargo workspace:
#
#   docker build -f infra/docker/vti.Dockerfile -t openvtc-research/vti:local .
#
# (run from the repository root; docker compose does this for you). The
# build-context excludes live in vti.Dockerfile.dockerignore beside this file,
# which BuildKit picks up automatically for this Dockerfile.
#
# One image, four binaries, one cargo invocation (the dependency graph is
# compiled once):
#   /usr/local/bin/vta   vta-service   (VTA daemon + offline admin CLI)
#   /usr/local/bin/vtc   vtc-service   (VTC daemon + offline admin CLI), built
#                                      with `vetting-pcs` for hidden vetting
#   /usr/local/bin/pnm   pnm-cli       (VTA admin client)
#   /usr/local/bin/cnm   cnm-cli       (VTC admin client)
#
# Feature choices, per package (every package is built --no-default-features,
# so each list below is explicit):
#   vta-service: the crate's defaults MINUS `keyring` (no OS secret service in a
#                container; the stack uses the dev-only plaintext seed backend).
#   vtc-service: the crate's defaults MINUS `keyring`, PLUS `vetting-pcs`.
#   pnm-cli / cnm-cli: `config-session` instead of `keyring` (sessions in a
#                plain file under $HOME/.config — fine for a throwaway stack).
#
# The VTC admin console (a React app built by vtc-service's build.rs with npm)
# is NOT built by default: VTC_SKIP_ADMIN_UI_BUILD=1 is set and the console
# routes serve an empty bundle. Pass `--build-arg VTC_ADMIN_UI=build` to build
# it in a node stage first (pulls npm packages; needs network).

ARG VTC_ADMIN_UI=skip

# -----------------------------------------------------------------------------
# Optional: the VTC admin console bundle.
# -----------------------------------------------------------------------------
FROM node:22-bookworm-slim AS admin-ui
ARG VTC_ADMIN_UI
WORKDIR /ui
COPY vti/vtc-service/admin-ui/ ./
RUN if [ "$VTC_ADMIN_UI" = "build" ]; then \
        npm ci && npm run build && npm run build:members; \
    else \
        mkdir -p dist dist-members; \
    fi

# -----------------------------------------------------------------------------
# Rust build. Keep the version equal to the root rust-toolchain.toml.
# -----------------------------------------------------------------------------
FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang cmake libdbus-1-dev libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Parallel rustc jobs. Docker Desktop's default VM (~8 GiB) runs out of memory
# with one job per core; raise this on a bigger build host. The workspace's own
# [profile.release] (thin LTO, codegen-units = 1) is used unchanged.
# One job: two generated Trust Task crates (vti-specs-*, ~20 MB of Rust each)
# compiling at once exceed an 8 GB Docker VM. Raise it on a bigger machine.
ARG CARGO_BUILD_JOBS=1
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
COPY . .
COPY --from=admin-ui /ui/dist/ vti/vtc-service/admin-ui/dist/
COPY --from=admin-ui /ui/dist-members/ vti/vtc-service/admin-ui/dist-members/
ENV VTC_SKIP_ADMIN_UI_BUILD=1
# The workspace release profile (codegen-units = 1, thin LTO) makes rustc hold
# each generated Trust Task crate (vti-specs-*) whole while optimising it; two
# at once exceed an 8 GB Docker VM and get OOM-killed. A local stack does not
# need the smallest binary, so the image relaxes both.
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    CARGO_PROFILE_RELEASE_LTO=off
# The generated wire types gain nothing from heavy optimisation.
ARG SPECS_OPT='--config profile.release.package.vti-specs.opt-level=1 --config profile.release.package.vti-specs-core.opt-level=1 --config profile.release.package.vti-specs-rooms.opt-level=1 --config profile.release.package.vti-specs-vta.opt-level=1 --config profile.release.package.vti-specs-vtc.opt-level=1 --config profile.release.package.vti-specs-vtn.opt-level=1'
# One cargo invocation per package, as upstream VTI's Dockerfile does: in a
# single multi-package `--no-default-features` build the `pkg/feature` flags did
# not all reach `vta-service` / `vtc-service` (e.g. `rest`), and both failed to
# compile. Each set below is checked to build on its own.
ARG VTA_FEATURES="setup,rest,didcomm,tsp,cli-synthesis,webs,webvh,jemalloc"
ARG VTC_FEATURES="setup,website,admin-ui,tsp,jemalloc,vetting-pcs"
ARG PNM_FEATURES="config-session,tsp"
ARG CNM_FEATURES="config-session"
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target,id=openvtc-research-vti-target \
    cargo build ${SPECS_OPT} --release --locked -p vta-service --no-default-features --features "${VTA_FEATURES}" && \
    cargo build ${SPECS_OPT} --release --locked -p vtc-service --no-default-features --features "${VTC_FEATURES}" && \
    cargo build ${SPECS_OPT} --release --locked -p pnm-cli --no-default-features --features "${PNM_FEATURES}" && \
    cargo build ${SPECS_OPT} --release --locked -p cnm-cli --no-default-features --features "${CNM_FEATURES}" && \
    mkdir -p /out && \
    cp target/release/vta target/release/vtc target/release/pnm target/release/cnm /out/

# -----------------------------------------------------------------------------
# Runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates libdbus-1-3 wget curl jq && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --uid 1000 --system --home-dir /home/vti --create-home --shell /bin/sh vti && \
    mkdir -p /var/lib/vta /var/lib/vtc /home/vti/.config && \
    chown -R vti:vti /var/lib/vta /var/lib/vtc /home/vti
COPY --from=builder /out/vta /out/vtc /out/pnm /out/cnm /usr/local/bin/
USER vti
WORKDIR /home/vti
EXPOSE 8100 8200
