# Provenance of `infra/`

`infra/` runs the services the vetting flows need but that are **not under
study**: a DIDComm mediator and a did:webvh hosting service. They are vendored
as source snapshots (no `.git`), each its own cargo workspace, built by the
Dockerfiles in `infra/docker/`. The services under study (VTA, VTC, `pnm`,
`cnm`, the OpenVTC client and PCS) are **not** vendored here: their images are
built from this repository's root cargo workspace.

## Vendored sources

| Directory | Upstream | Commit | Commit date | Exported from |
|---|---|---|---|---|
| `vendor/mediator/` | https://anonymized.example | `[withheld for review]` | 2026-11-17 | `origin/main` (workspace version 0.54.0) |
| `vendor/did-hosting/` | https://anonymized.example | `[withheld for review]` | 2026-11-17 | `origin/main` (crates at 0.12.0) |

Both were exported with `git archive <sha>`, so only tracked files came along
(no build output, no untracked files, no local branch state). License: Apache-2.0
for both (`LICENSE` and `NOTICE.txt` kept in each tree).

To refresh one: export the new commit the same way, re-apply the reductions and
patches below, and update this table.

## What was removed (build/run only needs the rest)

**mediator** — `.github/`, `fuzz/`, `interop/`, `changelog.d/`, `scripts/`,
`docs/`, CHANGELOG/RELEASES/CONTRIBUTING/CLAUDE.md, the
`docker/{ci,smoke,test,did-web,quickstart}` trees and upstream Dockerfile, the
crates `affinidi-messaging-mediator-admin`, `affinidi-messaging-mediator-tui`,
`affinidi-messaging-test-mediator` and `affinidi-messaging-mediator-processors`
(removed from `[workspace] members`). `Cargo.lock` was then re-resolved offline
(`cargo metadata --offline`): the only change is the removal of those four
crates and `affinidi-messaging-didcomm-service` (used only by them); no
version of any remaining package changed.

**did-hosting** — `.github/`, `did-hosting-ui/` (the web console; the image is
built without the `ui` feature), `docs/`, `examples/`, `fuzz/`, `changelog.d/`,
`scripts/`, CHANGELOG/RELEASES/CONTRIBUTING/CLAUDE.md, `lychee.toml`. Workspace
members and `Cargo.lock` are unchanged. Added `.dockerignore`.

## Local patches

The full diffs against upstream are in `vendor/patches/`
(`mediator-local.patch`, `did-hosting-local.patch`). Both patches do the same
one thing, and change nothing unless an environment variable is set:

The stack publishes every `did:webvh` on `localhost` (that is what keeps it
offline). The DID resolver both services use refuses loopback/private hosts by
default (`HostPolicy::PublicOnly`, `didwebvh-rs` ≥ 0.7). The VTI services
already have an opt-in for local development (`VTA_ALLOW_PRIVATE_ENDPOINTS`);
the mediator and the DID host did not, so:

- **mediator** (`crates/affinidi-messaging-mediator/src/common/config/mod.rs`):
  `MEDIATOR_ALLOW_PRIVATE_DID_HOSTS=1` makes the mediator's resolver use
  `HostPolicy::AllowPrivate`. Needed so the mediator can authenticate the VTA,
  the VTC and persona DIDs. The same variable also lifts the private-host
  check of the Trust Task proof verifier's resolver
  (`messages/protocols/trust_task_verify.rs`, `signing_key_resolver`); without
  it the mediator refuses the VTC's `messaging/message/status` checks on its
  own deliveries.
- **did-hosting** (`did-hosting-common/src/research_local.rs`, used by the
  resolver constructions in `did-hosting-common` and
  `did-hosting-server/src/bootstrap.rs`, and by
  `TransportBoundVerifier::with_did_cache`):
  `DID_HOSTING_ALLOW_PRIVATE_DID_HOSTS=1` does the same for the DID host, which
  must resolve the VTA's DID to verify the Trust Tasks the VTA signs when it
  publishes persona DIDs.

`docker-compose.yml` sets both variables. Neither patch should ever be used in
a deployment.

## Build-time deviations (Dockerfiles, not source)

- Images for the two infrastructure services are built with
  `CARGO_PROFILE_RELEASE_LTO=off` and `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`
  (cheaper builds; upstream uses LTO and one codegen unit) and a reduced
  feature set: mediator without the AWS secret/publish backends;
  did-hosting-daemon with `store-fjall,did-methods,jemalloc` only (no web
  console, no OS keyring).
- The VTA/VTC image (`docker/vti.Dockerfile`) uses the root workspace's own
  release profile unchanged.

## Third-party components that are neither [vendor]/OpenVTC code nor standard base images

None are vendored. At **build time** the Dockerfiles download, as usual:

- Rust crates from crates.io, pinned by each workspace's `Cargo.lock`
  (`--locked`).
- npm packages for the VTC admin console (`vti/vtc-service/admin-ui`), pinned
  by its `package-lock.json` (`npm ci`), only when building with
  `VTC_ADMIN_UI=build` (the compose default).

Base images (all official Docker Hub images): `rust:1.95.0-slim-bookworm`,
`rust:1.100.0-bookworm`, `debian:bookworm-slim` (pinned by digest, the same
digests the upstream Dockerfiles use), `node:22-bookworm-slim` (VTC console
build stage) and `redis:7-alpine` (runtime). Redis is the only third-party
service the stack runs.
