# infra: a local stack for OpenVTC vetting flows

This directory brings up, on one machine and with no outside services, the
processes an OpenVTC vetting flow runs against:

| Service | What | Source | Port (127.0.0.1) |
|---|---|---|---|
| `redis` | the mediator's store | `redis:7-alpine` | not published |
| `mediator` | DIDComm mediator, `did:peer` identity | `vendor/mediator` (vendored, see [PROVENANCE.md](PROVENANCE.md)) | 7037 |
| `did-hosting` | did:webvh hosting; the VTA publishes persona DIDs here | `vendor/did-hosting` (vendored) | 8534 |
| `vta` | the Verifiable Trust Agent (holds every key, runs the PCS engine) | `vti/vta-service` (root workspace) | 8100 |
| `vtc` | the community, built with `vetting-pcs` | `vti/vtc-service` (root workspace) | 8200 |
| `tools` | `pnm` (VTA admin) and `cnm` (VTC admin), on demand | `vti/pnm-cli`, `vti/cnm-cli` | — |

The OpenVTC client (`openvtc/`) runs on the host, one profile per person.

Everything is throwaway: plaintext key files in Docker volumes, no TLS, an
open mediator. Do not expose it.

## How it fits together

```
 host                                 Docker (one shared network namespace)
 ─────────────────────────────        ──────────────────────────────────────────────
 openvtc -p alice  ─┐                  redis ◄── mediator :7037 (did:peer)
 openvtc -p bob    ─┼─ localhost ────► did-hosting :8534  did:webvh:…:localhost%3A8534
 openvtc -p carol  ─┤                  vta :8100   did:webvh:…:localhost%3A8100  (self-hosted)
 browser (console) ─┘                  vtc :8200   did:webvh:…:localhost%3A8200  (self-hosted)
 ./bin/pnm, ./bin/cnm ──────────────►  tools (pnm, cnm)
```

Every container joins the network namespace of a small `net` container
(`network_mode: service:net`), and `net` publishes the four ports on
127.0.0.1. So **`localhost:<port>` means the same service inside every container
and on the host**. That is what lets the stack use `did:webvh` DIDs on
`localhost` — the simplest method that resolves fully offline and still gives
the VTA and VTC the DIDComm/REST service endpoints the flows need:

- the VTA's own DID is a root `did:webvh` it serves itself
  (`http://localhost:8100/.well-known/did.jsonl`);
- the community's DID is a serverless `did:webvh` the VTC serves itself
  (`http://localhost:8200/.well-known/did.jsonl`);
- persona DIDs (applicants, vetters) are minted by the VTA and published on the
  DID host (`http://localhost:8534/<path>/did.jsonl`);
- the mediator is a self-resolving `did:peer`.

Resolvers refuse `localhost` DIDs by default. Every process opts in:
`VTA_ALLOW_PRIVATE_ENDPOINTS=1` for VTI processes (`vta`, `vtc`, `pnm`, `cnm`
and — see the warning in §5 — `openvtc`), and two small, env-gated local patches
for the mediator and the DID host ([PROVENANCE.md](PROVENANCE.md#local-patches)).

**One VTA serves everybody**: the community's identity lives in its
`community` context, each OpenVTC profile in its own context. That keeps the
stack small, but it means one operator holds the community's keys *and* every
applicant's and vetter's PCS keys. Fine for exercising the protocol; do not
read privacy results off it. A second VTA for the people is a straightforward
extension (another `vta` service on its own port and volume, its own `pnm`
slug, the DID host registered on it).

## 0. Prerequisites

- Docker with Compose v2 (Docker Desktop on macOS works). **Give Docker at
  least 8 GB of memory**; 12 GB+ is comfortable. Rust builds are memory-bound:
  the mediator and DID-host Dockerfiles default to `CARGO_BUILD_JOBS=2` and the VTI image to `1` (its generated Trust Task crates are ~20 MB of Rust each), so they fit in 8 GB. With
  more memory, build faster with
  `docker compose build --build-arg CARGO_BUILD_JOBS=8`.
- ~25 GB free disk for images and build caches.
- On the host, the Rust toolchain from `rust-toolchain.toml` to build the
  OpenVTC client, and a browser that can create a passkey (for the VTC admin
  console; `localhost` counts as a secure context for WebAuthn).

## 1. Build

```sh
cd infra
docker compose build
```

Three images: `openvtc-research/mediator:local` and
`openvtc-research/did-hosting:local` (built from `vendor/`), and
`openvtc-research/vti:local`, built from the **repository root** workspace,
which carries `vta`, `vtc` (with `vetting-pcs`), `pnm` and `cnm`
(`docker/vti.Dockerfile`; it is used by the `vta`, `vtc` and `tools` services).
The first build compiles three large Rust dependency graphs and takes a long
time (tens of minutes); rebuilds reuse BuildKit cache mounts.

The VTC admin console is built in a Node stage (`npm ci`) by default. To skip
it (no console, so no passkey step-up — you cannot then add join criteria; see
§4): `VTC_ADMIN_UI=skip docker compose build vta`.

## 2. Bring it up and provision it

```sh
./bootstrap.sh
```

It is idempotent (re-run it after fixing whatever stopped it) and does,
using the non-interactive setup paths the VTI docs describe:

1. Starts `net`, `redis`, `mediator`, `did-hosting`. The mediator generates its
   identity on first start (`mediator-setup --from config/mediator-build.toml`,
   the upstream quickstart recipe); the DID host sets itself up self-managed
   (`did-hosting-daemon setup --from config/did-hosting-daemon.toml`).
2. **VTA** — `vta setup --from` ([`vti/docs/02-vta/non-interactive-setup.md`](../vti/docs/02-vta/non-interactive-setup.md);
   inputs in `config/vta-setup.toml.tmpl`): fresh seed (plaintext backend),
   DIDComm via the mediator, root `did:webvh` on `localhost:8100`. **The VTA is
   left unsealed** (no `admin_did`) so offline grants stay possible. Then the
   two-phase `pnm setup --name research-vta` / offline `vta import-did` /
   `pnm setup continue` ("Non-interactive `pnm setup`" in the same doc):
   `./bin/pnm` is the VTA's administrator.
3. **DID host** — gives the VTA's DID an `owner` entry on the DID host
   (`did-hosting-daemon add-acl`, offline) and registers the host at the VTA
   (`pnm did-mgmt servers add --id local`). OpenVTC needs this: it mints persona
   DIDs on the VTA's first WebVH server.
4. **VTC** — the two-phase headless setup
   ([`vti/docs/03-vtc/non-interactive-setup.md`](../vti/docs/03-vtc/non-interactive-setup.md);
   inputs in `config/vtc-setup.toml.tmpl`): `vtc setup --setup-key-out`, the
   grant at the VTA (`pnm contexts create --id community … --admin-handoff`),
   `vtc setup --from`. The community is installed in **single-administrator
   mode** (so one person's passkey gesture is enough to change join criteria)
   with a serverless `did:webvh` on `localhost:8200`. Then, following Path B of
   [`bootstrap-runbook.md`](../vti/docs/03-vtc/bootstrap-runbook.md), offline
   admin entries for an automation `did:key` (`vtc create-did-key --admin`) and
   for the `cnm` profile (`cnm community add` + `vtc acl add` +
   `cnm community continue`), and a 24-hour passkey invitation for you
   (`vtc admin invite`).
5. Writes `.state/stack.env` (all DIDs) and prints a summary.

`.state/` (git-ignored, mode 700) also keeps setup logs, the VTC setup's admin
key, the automation credential and the invitation.

Health: `docker compose ps` (every service `healthy`). Logs:
`docker compose logs -f vtc`. Stop: `docker compose down` (state kept in
volumes). Start again: `docker compose up -d`. Start over: `./reset.sh`
(deletes every volume and `.state/`).

Admin helpers:

| | |
|---|---|
| `./bin/pnm …` | `pnm` against the VTA (e.g. `./bin/pnm acl list`, `./bin/pnm contexts list`) |
| `./bin/cnm …` | `cnm` against the VTC (e.g. `./bin/cnm vetting vetters list`) |
| `./bin/vta-offline …` | an offline `vta` command (stops/restarts the VTA) |
| `./bin/vtc-offline …` | an offline `vtc` command (stops/restarts the VTC), e.g. `./bin/vtc-offline admin invite --ttl 3600` |

## 3. Claim the console (one human step)

Open the invitation printed at the end of `bootstrap.sh` (also in
`.state/vtc-admin-invite.txt`): the URL in a browser, then the claim code, then
register a passkey. Sign in at <http://localhost:8200/admin/>. If the invitation
expired: `./bin/vtc-offline admin invite --ttl 86400`.

This is required, not cosmetic. Adding, changing or removing a join criterion,
and turning hidden vetting on, take the requester's **passkey gesture bound to
that one change** (VTI-APV-023; [`join-criteria.md`](../vti/docs/03-vtc/join-criteria.md#who-may-change-them)).
There is no way to make that gesture from a script; `cnm` has no criteria
commands, and a bearer-token `POST /v1/schemas/accepts` (as in
`openvtc/docs/design/hidden-vetting-live-run.md` §2) is answered with a
step-up request rather than applied.

## 4. Set up vetting in the community

Follow the order in [`bootstrap-runbook.md` Part 2](../vti/docs/03-vtc/bootstrap-runbook.md#part-2--the-first-vetter)
— a vetter must already be a member, and an administrator can never be one.
You need OpenVTC profiles for the people first (§5); come back here once each
has a persona DID.

1. **Admit the vetters-to-be** (say Carol, Dave and Erin). Either issue each an
   invitation in the console (**Invitations**; they join with `--invitation`),
   or admit them directly:

   ```sh
   ./bin/cnm members admit <carol's persona DID> --role member
   ```

2. **Name them vetters**:

   ```sh
   ./bin/cnm vetting vetters grant <carol's persona DID> --validity 365d
   ./bin/cnm vetting vetters list
   ```

3. **Add a vetting criterion** (console: **Vetting → Requirements → Add a
   criterion**, then confirm with your passkey). For example, from the live-run
   doc: id `kernel-developer`, admission *automatic*, statement type
   `https://registry.trustoverip.org/dtg/vsc/vetted/1` (registered by default),
   3 statements, at least 1 in person, methods in-person and video, required
   claim `name.legal`, eligible vetters role `vetter`. This is **peer (named)
   vetting**. Per the runbook, it is decided after `review`; to make vetting the
   way in for applicants who name no criterion, remove `review` and add it back.
   See [`vetting.md`](../vti/docs/03-vtc/vetting.md) §1–2 for every field.

4. **Hidden vetting** (optional; the VTC is built with `vetting-pcs`): on the
   criterion's card, **Hidden vetting (PCS) → Turn on**, confirm with your
   passkey. The section then shows what is published (labels, drip rate,
   keys) and what is stored, and the dashboard's *Hidden vetting (PCS)* tile
   says the build supports it. The
   requirements digest moves when you turn it on (by design). Details:
   [`vetting.md` "Hidden vetting (PCS)"](../vti/docs/03-vtc/vetting.md#hidden-vetting-pcs)
   and [`openvtc/docs/design/hidden-vetting-live-run.md`](../openvtc/docs/design/hidden-vetting-live-run.md) §3–7.

## 5. Point OpenVTC clients at the stack

> **`VTA_ALLOW_PRIVATE_ENDPOINTS=1` must be set for the client too.**
> Resolvers refuse DIDs on loopback hosts by default. The OpenVTC client honours
> the same opt-in as the VTI services: every resolver and TDK instance it builds
> takes its host policy from `openvtc_core::resolver_policy`. `stack.env`
> (sourced below) sets the variable.

Build the client on the host and keep each person's profile apart:

```sh
cargo build --release -p openvtc            # from the repository root
set -a; . infra/.state/stack.env; set +a    # VTA_DID, VTC_DID, VTA_ALLOW_PRIVATE_ENDPOINTS=1
export OPENVTC_CONFIG_PATH="$HOME/.openvtc-research"
export OPENVTC_SECURE_STORE=file            # Linux only, optional: encrypted-file storage instead of the keyring.
                                            # On macOS leave it unset; setup asks for Keychain access once per profile.
alias openvtc="$PWD/target/release/openvtc"
```

For each person (`alice` the applicant, `carol`, `dave`, `erin` the vetters):

```sh
printf 'correct horse battery\n' > /tmp/alice.unlock   # the profile's unlock code
openvtc -p alice setup --vta-did "$VTA_DID" --unlock-code-file /tmp/alice.unlock
```

`setup` prints the grant to make at the VTA and waits for it. Run the printed
`pnm` command through the wrapper, e.g.

```sh
infra/bin/pnm contexts create --id openvtc-alice --name alice \
  --admin-did <the did:key it printed> --admin-expires 1h --admin-handoff --admin-holder
```

(copy the command exactly as printed: the flags matter; the context id must be
unique per profile). Then:

```sh
openvtc -p alice health --allow-private-probes   # resolves VTA, mediator, community
openvtc -p carol community join "$VTC_DID"       # first join mints the persona DID (on the DID host)
```

Then do §4 for the vetters, and walk the flows in the TUI (`openvtc -p <name>`):

- **Peer vetting.** The applicant starts an application to the community; on
  the vetting desk it gathers statements for the criterion; each vetter runs
  the ceremony (ticket, session, Vetting Card) and signs a statement; the
  applicant submits. Design: `openvtc/docs/design/vetting-process.md`.
- **Hidden vetting.** As each vetter, vetting desk → **`m`** repeatedly
  (manifest, enrolment, first token drip); as the applicant, **`m`** on the
  application ("their names never reach this community"), the same ceremony,
  then submit one proof. Then
  `GET http://localhost:8200/v1/join-requests/<id>/vetting` (admin) or the
  console's join request shows three tags where three DIDs would be.
  Walkthrough: `openvtc/docs/design/hidden-vetting-live-run.md` §5–7.

## What was verified, and what was not

Verified on 2026-11-18 with Docker Desktop on macOS (arm64, 8 GB VM):

- `docker compose config` validates. All three images build, including
  `openvtc-research/vti:local`. The VTI build takes over an hour with one job.
- **`./bootstrap.sh` runs all five steps** on a fresh stack. Afterwards every
  service is healthy:
  - `livez` and `/health` answer for the mediator, the VTA and the VTC.
  - The VTA and VTC serve their `did:webvh` logs on `localhost`.
  - `./bin/pnm acl list` works.
  - The console invitation is written to `.state/`.
- **An `openvtc` client sets up against the stack** (`openvtc -p alice setup
  --vta-did …`, §5):
  - It resolves the VTA's `localhost` DID and the mediator.
  - It mints its setup DID and prints the `pnm` grant.
  - Once `./bin/pnm contexts create …` runs, it opens a DIDComm session with
    the VTA through the mediator.
  - It then stops at the OS secure-storage prompt (the macOS Keychain
    dialog), which needs a person.
- The vetting protocols themselves are covered by the in-process demos
  (`../scripts/run-demos.sh`), which run the same VTA, VTC and client code.

Not verified:

- **Walking a full vetting flow across several `openvtc` profiles in the TUI**
  (§4–5). This needs the console passkey claim and the Keychain prompts, which
  are human steps.
- Whether the VTA publishes persona DIDs to the DID host without further
  configuration. This happens on a profile's first community join.

## Scripting the console steps (`bin/console`)

`./bin/console` drives the real admin console in headless Chrome over the Chrome
DevTools Protocol. A CDP WebAuthn virtual authenticator acts as the passkey.
Nothing on the server is bypassed: every criteria change still takes a passkey
assertion bound to that change (VTI-APV-023), and the virtual authenticator
makes it. It needs Node 22+ and Chrome at `/Applications/Google Chrome.app`
(`CHROME_BIN` overrides the path). It installs no packages.

```sh
./bin/console claim                      # claims .state/vtc-admin-invite.txt, then signs in
./bin/console add-criterion scripts/console/criterion-peer.json     # kernel-developer (exits 0 if it exists)
./bin/console add-criterion scripts/console/criterion-hidden.json   # kernel-developer-hidden
./bin/console hidden-on kernel-developer-hidden                     # prints labels, drip rate, keys
./bin/console remove-criterion review    # then add it back, so it is decided last:
./bin/console add-criterion scripts/console/criterion-review.json
./bin/console show                       # criteria in decision order, with digests, as JSON
./bin/console join-requests              # pending join requests
./bin/console approve-join <request id | persona DID>
```

Order: add the vetting criteria first, then move `review` to the end
(`remove-criterion review`, then `add-criterion criterion-review.json`). New
criteria go last, so without the move `review`, which asks for nothing, decides
every applicant who names no criterion. Only one criterion can have hidden
vetting at a time.

State, all under `.state/`:

- `console-passkey.json` holds the passkey credential, private key included.
  It is re-added on every run. Its signature counter is raised by 1000 on each
  run, because the VTC refuses an assertion whose counter does not go up.
- `console-chrome/` holds the browser profile, the session cookies and
  `failure-*.png` screenshots.
- `console-removed-<id>.json` holds a copy of each removed criterion.

The VTC allows each address a burst of 10 anonymous calls, then one every 5 s,
and every host client shares that budget. Console-key reads count against it
too. The script drops the sign-in page's unused wallet and theme calls, and it
retries a rate-limited sign-in after the wait the VTC names. Running it while
`openvtc` clients are busy can still make it wait.

## Automated vetting run (no human in the loop)

`scripts/vetting-run.sh` walks people through vetting against this stack with
the real OpenVTC client and no TUI:
- **carol** and **dave**: vetters.
- **alice**: peer vetting.
- **bob**: hidden vetting.

Each person is one `openvtc` process, driven by `openvtc script …` (feature
`scripted`, `openvtc/openvtc/src/script_cmd.rs`). That mode runs the client's
own state handler, VTA session, mediator listeners and inbound handling, and
sends the actions the TUI's keys would send. The admin's steps go through
`bin/console`, the console driven with a virtual passkey, and `bin/cnm`.

```sh
cargo build -p openvtc --features scripted          # from the repository root
infra/bin/console claim                             # once
infra/bin/console add-criterion infra/scripts/console/criterion-peer.json
STEP_TIMEOUT=300 infra/scripts/vetting-run.sh peer  # or: hidden, all
```

- `scripts/client-setup.sh <name>` creates a profile with no prompts. Keys are
  kept in the client's encrypted-file store (`OPENVTC_SECURE_STORE=file`), so
  there is no OS keychain dialog.
- `docker/openvtc.Dockerfile` (the compose `client` service, profile `clients`)
  builds the same client for Linux.
- Logs are in `.state/client-logs/`.

A vetter's client treats a community that hides any criterion's vetters as
hiding all of them. So the script runs peer vetting with no hidden criterion,
then adds `kernel-developer-hidden` and turns hidden vetting on for the hidden
run.

**Status (2026-11-18): in progress, not yet passing end to end.**

Verified against this stack:
- Profiles are created with no prompts.
- The vetters join with the administrator approving in the console.
- The membership credentials are delivered and stored.
- The vetter grants arrive.
- The applicant creates a persona, starts an application, and makes a face
  carrying its legal name.
- A vetter's ticket request reaches the community and asks how it vets.

Not yet passing: the ticket, request, session, card, attestation and join
steps. These are still being scripted against the live stack. The same
protocol steps pass in process (`../scripts/run-demos.sh`, demos `peer` and
`hidden`).

Getting this far found four client bugs that block any localhost stack. They
are fixed in this repository (see `PROVENANCE.md`):
- Two places still resolved DIDs with the public-only host policy.
- Membership credentials were refused because the community's status list was
  served over http.
- The community's manifest was refused over http.

The mediator's Trust Task proof verifier also needs its private-host opt-in
(`vendor/patches/mediator-local.patch`). The patched mediator image is not
built yet: the build needs more than an 8 GB Docker VM at its release
settings. Until it is rebuilt, the VTC logs refused delivery-status checks.
That is noise; delivery itself works.
