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
  the Dockerfiles default to `CARGO_BUILD_JOBS=2` so they fit in 8 GB. With
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

> **Known blocker — read this first.** The OpenVTC client in `openvtc/`
> resolves DIDs with resolvers built at their default host policy
> (`DIDCacheConfigBuilder::default()` / `TDKConfig::builder()`, about 37 places
> in `openvtc` and `openvtc-core`), and that default refuses every
> `localhost` DID before making a request. Unlike the VTI services it does
> **not** honour `VTA_ALLOW_PRIVATE_ENDPOINTS` for DID resolution (only
> `openvtc health --allow-private-probes` and the manifest probe take a private
> policy). Against this stack that breaks, at least, resolving the community
> DID, checking invitations and VICs, and verifying the community's
> signatures. The fix belongs in `openvtc/` (one resolver-config helper that
> applies `vta_sdk::resolver::webvh_host_policy()`, used everywhere a resolver
> or TDK is built); it is deliberately not made from `infra/`. The steps below
> are what to run once that is in place; they are untested end to end.

Build the client on the host and keep each person's profile apart:

```sh
cargo build --release -p openvtc            # from the repository root
set -a; . infra/.state/stack.env; set +a    # VTA_DID, VTC_DID, VTA_ALLOW_PRIVATE_ENDPOINTS=1
export OPENVTC_CONFIG_PATH="$HOME/.openvtc-research"
export OPENVTC_SECURE_STORE=file            # optional: keep keys out of the OS keychain
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

Verified when this directory was written (2026-11-17, Docker Desktop on macOS,
arm64, 8 GB VM):

- `docker compose config` validates.
- The mediator and DID-host images build from `vendor/` (with the local
  patches), and `redis`, `mediator` and `did-hosting` come up **healthy** under
  this compose file. The mediator generates its `did:peer` identity, answers
  `http://localhost:7037/mediator/v1/livez` from the host, and logs that its
  resolver runs with `AllowPrivate`. The DID host sets itself up self-managed,
  serves `did:webvh:…:localhost%3A8534` at `/.well-known/did.jsonl` to the host,
  and advertises `TrustTaskHTTPS` at `http://localhost:8534/api` (a loopback
  endpoint the VTA accepts). The offline `add-acl` / `list-acl` /
  `remove-acl` round trip `bootstrap.sh` uses works with the daemon stopped.
- `bootstrap.sh` step 1 (reading the mediator's and DID host's DIDs).
- `docker/vti.Dockerfile` mechanics: the root-context build with its
  `.dockerignore`, the admin-console Node stage (`npm ci`, both bundles), and
  compiling the whole third-party dependency graph with `CARGO_BUILD_JOBS=2`
  in 8 GB.

Not verified:

- The `openvtc-research/vti:local` image itself: the root workspace did not
  compile at the time (`vti/vti-voting` against the in-repo `pcs/` API —
  `predicate_credential_system::{cred, pcs}` not found — while the workspace
  was being restructured). Consequently **steps 2–5 of `bootstrap.sh` have not
  run**. They follow the documented commands and output formats; expect to fix
  small things (a flag spelling, a parse of some output) on the first run.
  Every step says what it is doing, and the script is safe to re-run.
- The VTA/VTC with `--no-default-features` (no `keyring`) and the plaintext
  secret backends, as configured here.
- The OpenVTC client against the stack (see the blocker in §5).
- Whether the VTA, once running, publishes persona DIDs to the DID host over
  its `TrustTaskHTTPS` endpoint without further configuration.
