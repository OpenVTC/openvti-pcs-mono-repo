# Provenance

This repository is a source snapshot assembled for review. Each directory
comes from an upstream repository at a fixed commit. The upstream history is
not included.

**Anonymised for review.** Personal names, email addresses and handles, and
the links and names of the organisations and projects behind this code have
been removed or replaced (`https://anonymized.example`, `[vendor]`,
`[network]`, `[foundation]`). Upstream repositories and commit hashes are
withheld until after review. Two kinds of name are kept on purpose:

- **Functional identifiers**, which the code would break without: crates.io
  dependency names, and protocol URIs inside the specifications and the code
  (Trust Task type URIs, credential type and DIDComm message type URIs).
- **The copyright notice in `pcs/LICENSE`**, which the MIT licence requires
  to be kept.
- **Vendored Trust Task specification bundles** (`vti/*/trust-tasks/**`),
  which are published specification text pinned by hash in each
  `trust-tasks.lock`; two of them (`device/list/0.3`, `device/register/0.2`)
  use a personal first name as example data.

The git history of this repository is not anonymised.

| Directory | Upstream | Ref | Commit | Licence |
|---|---|---|---|---|
| `pcs/` | https://anonymized.example | `feat/pcreds-jali-0.3` | `[withheld for review]` | MIT (`pcs/LICENSE`) |
| `vti/` | https://anonymized.example | `main` | `[withheld for review]` | Apache-2.0 (`vti/LICENSE`) |
| `openvtc/` | https://anonymized.example | `main` | `[withheld for review]` | Apache-2.0 (`openvtc/LICENSE`) |
| `vgi/did-git-sign/` | https://anonymized.example | `v0.33.0` | `[withheld for review]` | Apache-2.0 (`vgi/LICENSE`) |
| `infra/vendor/*` | see `infra/PROVENANCE.md` | | | |

Every other crate is resolved from crates.io at the versions pinned in
`Cargo.lock`. That includes the [vendor] Trust Development Kit, the
`trust-tasks-*` crates, arkworks, Jali and `ntru-trapdoor`.

## What was taken

- **`pcs/`**: the `predicate-credential-system` crate and its hidden-vetting
  prototype (`pcs/demo`, package `pcs-vetting-prototype`).
- **`vti/`**: the crates the VTA (`vta-service`) and the VTC (`vtc-service`)
  need to build, plus the two admin CLIs (`pnm-cli` for the VTA and `cnm-cli`
  for the VTC) and `vti/docs`. `room-host`, `vti-witness` and
  `vti-voting-service` are included only because other crates' end-to-end
  tests run them in process.

  Left out because the vetting flows don't use them: the mobile engine
  (`vta-mobile-core`), the MCP bridges (`vta-mcp`, `vtc-mcp`,
  `vti-mcp-common`), the Nitro enclave build (`vta-enclave`, `deploy/`), the
  WASM rooms client, `didcomm-test`, the fuzz harness and the repository's CI
  and release tooling.
- **`openvtc/`**: the `openvtc` TUI client and `openvtc-core`.
- **`vgi/did-git-sign/`**: OpenVTC's commit signer. It is vendored rather than
  taken from crates.io because the published release depends on an older
  `vta-sdk`, and with it the workspace would contain two copies of `vta-sdk`.

## Changes from upstream

All the changes are in this repository's git history (`git log -p`).

1. **One workspace.** The root `Cargo.toml` replaces the three upstream
   workspace manifests. Inter-project dependencies point at the in-repo
   source (`vta-sdk`, `vta-service`, `vti-vetting-pcs`, `vti-voting`,
   `predicate-credential-system`, `did-git-sign`).
2. **OpenVTC moved forward to the VTI commit above.** Upstream, OpenVTC
   `main` builds against published releases (`vta-sdk` 0.80). Here it builds
   against VTI `main` (`vta-sdk` 0.90). Listing DIDs moved from the
   webvh-only `list_dids_webvh` to the method-neutral `vta/dids/list` (VTI
   #2763). ACL updates gained the `purposes` member.
3. **OpenPGP-card support is off by default** in `openvtc` and `openvtc-core`.
   It needs PC/SC and isn't part of vetting. The code is still there behind
   the `openpgp-card` feature.
4. **`did-git-sign`** was adapted to `vta/dids/list` and keeps `sysinfo` 0.39.
5. **VTI ported to the `pcreds` API** of `pcs/` (`feat/pcreds-jali-0.3`).
   Upstream VTI is built on the published PCS 0.1, whose API was replaced.
   The port follows `pcs/demo`:
   - **Periods.** Each vetter period is its own helper key, derived
     deterministically from the community's secret. An application lives in
     one period.
   - **Tokens.** One PS key per attestation-token label.
   - **Elections.** One registrar key per election.
   - **Root admission.** A credential request with no attestations. The
     session id is rebuilt for the submitting member.
   - **Hardening carried over from the demo.** The demo's review fixes are
     carried over: at most 64 attestations per request, duplicate tags
     refused, and a vetter's token spent only after its attestation succeeds.

   JSON message shapes are unchanged. Some opaque values changed meaning:
   `helperKey` and `tokenKey` are now per-label key lists, and the applicant's
   `id` is now an `ApplicantRef` (label, session id, identifier and `π_id`)
   rather than a point. Persisted state formats changed, with no migration.

   **Where the integration departs from the paper's protocol.** This list is
   for reviewers:
   - **`π_id` is bound to the community, not to each vetter.** The VTA builds
     the applicant's reference once, before it knows the vetters, so anyone
     holding a copy can present it to another vetter. Binding per vetter
     needs one VTA call per vetter.
   - **`π_id`'s nonce is derived.** It is `SHA-256(usk ‖ ssid ‖ community)`,
     seeding ChaCha20, so the reference is stable across calls. This has not
     been reviewed.
   - **A vetter keeps one `usk` across periods.** It is derived from a seed.
     If that key is ever recovered, it links the vetter's periods.
   - **"Issue once per identifier" is enforced by the VTC's durable records,**
     not the helper's in-memory issuance record. This allows a bounded
     re-issue to a client that lost an answer.
   - **The community evaluates requests from public data only.** It
     reimplements `evaluate_request_at` with the library's public checks,
     because `Protocol::evaluate_request` needs the signing key. One
     difference: duplicate tags are refused outright, not retried.
   - **A vote cast calls the backend's attestation proof directly** at
     `x_E = H_req(pp, hvk_E, Election::point())`, outside the `attest` flow.
     Its soundness rests on `x_E ≠ x_0`.
6. **`pcs/demo`** depends on the in-repo `vta-sdk` instead of the pinned
   `=0.56.1`. One renamed constant was updated (`VETTED_PREDICATE`).
7. **OpenVTC honours `VTA_ALLOW_PRIVATE_ENDPOINTS`**, as the VTI services do,
   so the client works against the `localhost` stack in `infra/`. Without the
   variable, behaviour is unchanged.
   - Every resolver and TDK instance the client builds takes its host policy
     from `openvtc-core/src/resolver_policy.rs`. That includes the runtime's
     own TDK in `state_handler/mod.rs`.
   - Under the opt-in, a community's status list (`vetting/status.rs`) and
     manifest (`join/sequence.rs`) may be fetched over http from a private
     host. Without that, the client refuses a membership credential whose
     revocation status it cannot check.
   - **A research harness, `openvtc script …`**, sits behind the off-by-default
     feature `scripted` (`openvtc/src/script_cmd.rs`). It drives the real state
     handler with the TUI's actions instead of a terminal, and in that build
     the encrypted-file key store is allowed on any Unix. It is used by
     `infra/scripts/vetting-run.sh`.
8. **OpenVTC's tests** take `MockVta` from `vta-test-support`, where it now
   lives, and follow the `pcreds` API changes.
9. Removed: release, CI and process files (`CHANGELOG.md`, `CLAUDE.md`,
   `RELEASES.md`, `.github/`, release scripts).
