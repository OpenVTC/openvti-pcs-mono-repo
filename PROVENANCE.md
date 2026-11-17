# Provenance

This repository is a source snapshot assembled for review. Each directory
comes from an upstream repository at a fixed commit. The upstream history is
not included.

| Directory | Upstream | Ref | Commit | Licence |
|---|---|---|---|---|
| `pcs/` | https://github.com/OpenVTC/predicate-credential-system | `feat/pcreds-jali-0.3` | `023b13d18562a546ce1e98f24383ea2d6b270754` | MIT (`pcs/LICENSE`) |
| `vti/` | https://github.com/OpenVTC/verifiable-trust-infrastructure | `main` | `32cd9ff724aac19a81bb622aaa6d1fd6d0d65baf` | Apache-2.0 (`vti/LICENSE`) |
| `openvtc/` | https://github.com/OpenVTC/openvtc | `main` | `7fbe7a3d39a577605f3cc1fac7d497e933205928` | Apache-2.0 (`openvtc/LICENSE`) |
| `vgi/did-git-sign/` | https://github.com/OpenVTC/verifiable-git-infrastructure | `v0.33.0` | `27e0d34fee2429c11645092185ffc8dd19038db7` | Apache-2.0 (`vgi/LICENSE`) |
| `infra/vendor/*` | see `infra/PROVENANCE.md` | | | |

Every other crate is resolved from crates.io at the versions pinned in
`Cargo.lock`. That includes the Affinidi Trust Development Kit, the
`trust-tasks-*` crates, arkworks, Jali and `ntru-trapdoor`.

## What was taken

- **`pcs/`**: the `predicate-credential-system` crate. The prototype under
  `demo/` was left out because the integration in `vti/vti-vetting-pcs`
  replaces it.
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
5. **VTI ported to the `pcreds` API** of `pcs/` (`feat/pcreds-jali-0.3`). See
   the port notes in `vti/vti-vetting-pcs`.
6. Removed: release, CI and process files (`CHANGELOG.md`, `CLAUDE.md`,
   `RELEASES.md`, `.github/`, release scripts).
