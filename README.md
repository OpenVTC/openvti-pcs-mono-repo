# OpenVTC research mono-repo

This repository holds everything needed to read, build and run the **vetting
flows** of OpenVTC (Open Verifiable Trust Communities):

- **Peer vetting.** Existing members check an applicant's identity and sign
  Vetting Statements. The community counts the statements before admitting the
  applicant.
- **Hidden vetting.** The community admits an applicant on a zero-knowledge
  proof that enough distinct, eligible members vetted them. It never learns
  *which* members did. The proof comes from the **Predicate Credential System
  (PCS)**.

It is one Cargo workspace. All the code these flows run is in this repository.

| Directory | What it is |
|---|---|
| `pcs/` | The Predicate Credential System: the `pcreds` protocol (`Π_PCreds`) and its pairing-based and lattice-based instantiations. `pcs/demo/` is an in-memory prototype of hidden-vetter admission. |
| `vti/` | Verifiable Trust Infrastructure. **VTA** (`vta-service`): a person's agent, which holds their keys and runs their PCS engine. **VTC** (`vtc-service`): the community service, which sets the vetting criteria and admits members. `vti-vetting-pcs` is the hidden-vetting layer shared by the two; `pnm-cli` and `cnm-cli` are the admin CLIs. |
| `openvtc/` | The OpenVTC client: a terminal UI (`openvtc`) and its library (`openvtc-core`). Applicants and vetters use it. |
| `vgi/` | `did-git-sign`, a dependency of the client. Not part of vetting. |
| `infra/` | A local Docker stack (mediator, DID host, VTA, VTC) for running the flows across real processes. |

`PROVENANCE.md` lists the upstream commit each directory comes from and every
change made here.

## Requirements

- Rust **1.100.0**. `rust-toolchain.toml` pins it, and `rustup` installs it
  automatically.
- For the local stack only: Docker with at least 8 GB of memory.

The first build compiles a large dependency graph and takes 10–20 minutes.

## 1. Run the demos (no setup)

Every demo runs in process, so nothing needs deploying:

```sh
./scripts/run-demos.sh              # all five, in order
./scripts/run-demos.sh pcs hidden   # or pick by name
```

| Name | What runs | Command |
|---|---|---|
| `pcs` | **PCS protocol.** A helper issues a credential once `k` distinct credentialed users attest for a user. The user then proves membership anonymously. Covers every base/tag pair over BLS12-381 and prints the size of each object. | `cargo test --release -p predicate-credential-system --test pcreds` |
| `prototype` | **Hidden-vetter admission prototype.** A VTC as PCS helper, vetters with periods and attestation tokens, and an applicant proving `k` distinct eligible vetters. Everything is in memory; there is no transport. | `cargo test --release -p pcs-vetting-prototype` |
| `engines` | **The production hidden-vetting engines.** The community's issuer and verifier, and the vetter and applicant engines the VTA runs, end to end. | `cargo test --release -p vti-vetting-pcs --test end_to_end` |
| `peer` | **Peer vetting ceremony.** An applicant and a vetter exchange the request, session, Vetting Card and Vetting Statement through a real DIDComm mediator. | `cargo test -p openvtc-core --test vetting_e2e -- --include-ignored` |
| `hidden` | **Hidden-vetting onboarding.** The OpenVTC client drives a real VTA (in process) and the VTC's decision code. Two vetters enrol and draw tokens, then attest. The applicant proves, and the community admits without learning who vetted. | `cargo test -p openvtc-core --test hidden_vetting_onboarding -- --include-ignored` |

Each test file opens with a comment that walks through the flow step by step.
Read those alongside the output.

### More PCS

```sh
cargo test --release -p predicate-credential-system                    # the full suite: correctness, soundness, adversarial, IETF vectors
cargo bench -p predicate-credential-system --bench pcreds              # prints every object's size, then times each party's algorithms (the paper's comparison table)
cargo test --release -p predicate-credential-system --features lattice --test lattice_flows   # post-quantum instantiation (slow, about 0.7 GB per proof)
cargo doc -p predicate-credential-system --open                        # API docs, with a paper-to-module map on the front page
```

`pcs/README.md` and `pcs/docs/` cover the PCS design, the encodings and the
testing approach.

## 2. Run a vetting process with real services

`infra/` brings up a DIDComm mediator, a did:webvh host, a VTA and a VTC (built
with hidden vetting) on `localhost`. You then use several `openvtc` clients:
one applicant and several vetters.

```sh
cd infra
docker compose build     # first build: 30+ minutes
./bootstrap.sh           # provisions the VTA and VTC, starts everything
```

Then follow `infra/README.md`:

1. **§3. Claim the VTC admin console.** This is a one-time passkey step in a
   browser at `http://localhost:8200/admin/`.
2. **§4. Configure vetting.** Add a join criterion that requires vetting
   statements, then turn on hidden vetting for it.
3. **§5. Create an `openvtc` profile for each person** and walk the flow in the
   terminal UI:
   - **Peer vetting:** the applicant applies, each vetter runs the ceremony and
     signs a statement, and the applicant submits.
   - **Hidden vetting:** the vetters enrol, the applicant applies, the same
     ceremony runs, and the applicant submits one proof. The VTC's join request
     shows anonymous tags where member DIDs would be.

Both the services and the client accept `localhost` DIDs only with
`VTA_ALLOW_PRIVATE_ENDPOINTS=1`. The stack sets it, and `infra/.state/stack.env`
exports it for the clients.

## Where to read

| Topic | Document |
|---|---|
| Hidden vetting design, including the threat model and the paper mapping | `openvtc/docs/design/vetting-hidden-vetters-pcs.md` |
| Peer vetting process | `openvtc/docs/design/vetting-process.md` |
| Running hidden vetting live | `openvtc/docs/design/hidden-vetting-live-run.md` |
| Community-side vetting and its wire types | `vti/docs/03-vtc/vetting.md` |
| The VTA as PCS engine, with the round-by-round task tables | `vti/docs/02-vta/pcs-engine.md` |
| System architecture | `vti/docs/01-concepts/` |
| PCS library | `pcs/README.md`, `pcs/docs/` |

## Status and caveats

- **Research code.** PCS is a research implementation and has not been
  audited. The stack in `infra/` uses plaintext key files and no TLS.
- **PCS is the `pcreds` version** (Jali 0.3, application contexts). VTI was
  ported to it for this repository; upstream VTI still uses the published PCS
  0.1. `PROVENANCE.md` lists where the port differs from the paper's protocol.
- Running `./scripts/run-demos.sh` exercises every flow above. The `infra/`
  stack's bring-up beyond the mediator and DID host is less tested; see
  `infra/README.md`, "What was verified".
