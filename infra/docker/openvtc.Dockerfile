# The OpenVTC client (`openvtc`), for running applicants and vetters against the
# stack from Linux containers. Linux lets the client keep its keys in its
# encrypted-file store (OPENVTC_SECURE_STORE=file), so no OS keychain or
# desktop prompt is involved, and the same run works on any host OS.
#
# Built from the repository root, like the VTI image:
#   docker compose --profile clients build client
FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang cmake libdbus-1-dev libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Same memory budget as the VTI image (docker/vti.Dockerfile): one job, no LTO,
# light optimisation for the generated Trust Task crates.
ARG CARGO_BUILD_JOBS=1
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS} \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    CARGO_PROFILE_RELEASE_LTO=off \
    VTC_SKIP_ADMIN_UI_BUILD=1
ARG SPECS_OPT='--config profile.release.package.vti-specs.opt-level=1 --config profile.release.package.vti-specs-core.opt-level=1 --config profile.release.package.vti-specs-rooms.opt-level=1 --config profile.release.package.vti-specs-vta.opt-level=1 --config profile.release.package.vti-specs-vtc.opt-level=1 --config profile.release.package.vti-specs-vtn.opt-level=1'
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target,id=openvtc-research-client-target \
    cargo build ${SPECS_OPT} --release --locked -p openvtc && \
    mkdir -p /out && cp target/release/openvtc /out/

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libdbus-1-3 jq && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --uid 1000 --system --home-dir /home/openvtc --create-home --shell /bin/sh openvtc
COPY --from=builder /out/openvtc /usr/local/bin/
USER openvtc
WORKDIR /home/openvtc
ENTRYPOINT ["openvtc"]
