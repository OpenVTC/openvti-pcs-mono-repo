#!/usr/bin/env bash
# Provision and start the OpenVTC research stack.
#
#   cd infra && ./bootstrap.sh
#
# Idempotent: every step checks whether it already ran (by looking in the
# service's volume or the CLI profiles), so a re-run after a failure picks up
# where it stopped. `./reset.sh` throws everything away.
#
# What it does, in order (README.md explains each):
#   1. start net, redis, mediator, did-hosting; read the mediator's and the
#      DID host's DIDs
#   2. VTA:  `vta setup --from` (unsealed, did:webvh on localhost:8100);
#            `pnm setup --name` (phase 1) + offline `vta import-did` grant;
#            start the VTA; `pnm setup continue` (phase 2) + `pnm health`
#   3. DID host: offline `add-acl` of the VTA DID (role owner); register the
#      host at the VTA (`pnm did-mgmt servers add`)
#   4. VTC:  `vtc setup --setup-key-out` (phase 1); grant at the VTA
#            (`pnm contexts create --admin-handoff`); `vtc setup --from`
#            (phase 2, serverless did:webvh on localhost:8200,
#            single-administrator mode); offline admin entries for an
#            automation did:key and for the cnm profile; a fresh admin
#            (passkey) invitation; start the VTC; `cnm community continue`
#   5. write .state/stack.env and print what to do next
#
# Needs: docker with compose v2, and the images built (`docker compose build`).

set -euo pipefail

INFRA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="${INFRA}/.state"
mkdir -p "${STATE}"
chmod 700 "${STATE}"

PNM_SLUG="research-vta"
VTC_CONTEXT="community"
VTC_NAME="Research community"
CNM_SLUG="research-community"
DID_HOST_ID="local"

dc() { docker compose -f "${INFRA}/docker-compose.yml" "$@"; }

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*" >&2; }
note() { printf '    %s\n' "$*" >&2; }
die()  { printf '\n\033[31mbootstrap: %s\033[0m\n' "$*" >&2; exit 1; }

# Offline VTA / VTC commands: a throwaway container on the service's volume.
# The daemon must not be running (the store is single-writer).
vta_offline() { dc run --rm --no-deps -T --entrypoint vta vta --config /var/lib/vta/config.toml "$@"; }
vtc_offline() { dc run --rm --no-deps -T --entrypoint vtc vtc --config /var/lib/vtc/config.toml "$@"; }
in_vta_vol()  { dc run --rm --no-deps -T --entrypoint sh vta -c "$1"; }
in_vtc_vol()  { dc run --rm --no-deps -T --entrypoint sh vtc -c "$1"; }
didhost_offline() {
    dc run --rm --no-deps -T --entrypoint /usr/local/bin/did-hosting-daemon did-hosting \
        -c /var/lib/did-hosting/config.toml "$@"
}
# Admin CLIs, sessions in the cli-home volume.
pnm() { dc run --rm -T tools pnm "$@"; }
cnm() { dc run --rm -T tools cnm "$@"; }
tools_sh() { dc run --rm -T tools sh -c "$1"; }

# Read `key = "value"` from a TOML file inside a container's volume.
toml_get() { # <runner> <file> <key>
    "$1" "sed -n 's/^$3[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*\$/\\1/p' '$2' | head -n1" | tr -d '\r'
}

wait_healthy() { # <service> [timeout-seconds]
    local svc="$1" timeout="${2:-300}" waited=0 cid status
    while :; do
        cid="$(dc ps -q "${svc}" 2>/dev/null || true)"
        if [[ -n "${cid}" ]]; then
            status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${cid}" 2>/dev/null || echo unknown)"
            [[ "${status}" == "healthy" ]] && return 0
        fi
        (( waited >= timeout )) && die "${svc} not healthy after ${timeout}s (status: ${status:-absent}). Check: docker compose logs ${svc}"
        sleep 3; waited=$((waited + 3))
    done
}

render() { # <template> <out>  (replaces ${VTA_DID} and ${MEDIATOR_DID})
    sed -e "s|\${VTA_DID}|${VTA_DID:-}|g" -e "s|\${MEDIATOR_DID}|${MEDIATOR_DID:-}|g" "$1" > "$2"
}

# ---------------------------------------------------------------------------
say "1/5 infrastructure: redis, mediator, did hosting"
dc up -d net redis mediator did-hosting
wait_healthy redis
wait_healthy mediator
wait_healthy did-hosting

MEDIATOR_DID="$(dc exec -T mediator sh -c "sed -n 's/^mediator_did[[:space:]]*=[[:space:]]*\"\\(.*\\)\"/\\1/p' conf/mediator.toml" | tr -d '\r')"
MEDIATOR_DID="${MEDIATOR_DID#did://}"
[[ "${MEDIATOR_DID}" == did:* ]] || die "could not read the mediator DID from conf/mediator.toml (got '${MEDIATOR_DID}')"
note "mediator DID: ${MEDIATOR_DID}"

DID_HOST_DID="$(dc exec -T did-hosting sh -c "sed -n 's/^server_did[[:space:]]*=[[:space:]]*\"\\(.*\\)\"/\\1/p' /var/lib/did-hosting/config.toml" | tr -d '\r')"
[[ "${DID_HOST_DID}" == did:* ]] || die "could not read server_did from the did-hosting config.toml"
note "DID host DID: ${DID_HOST_DID}"

# ---------------------------------------------------------------------------
say "2/5 VTA"
if [[ -z "$(in_vta_vol 'test -f /var/lib/vta/config.toml && echo yes' || true)" ]]; then
    render "${INFRA}/config/vta-setup.toml.tmpl" "${STATE}/vta-setup.toml"
    note "vta setup --from (fresh seed, did:webvh on localhost:8100)"
    dc run --rm --no-deps -T --entrypoint vta vta setup --from /state/vta-setup.toml
fi
VTA_DID="$(toml_get in_vta_vol /var/lib/vta/config.toml vta_did)"
[[ "${VTA_DID}" == did:webvh:* ]] || die "could not read vta_did from the VTA config (got '${VTA_DID}')"
note "VTA DID: ${VTA_DID}"

if [[ -z "$(in_vta_vol 'test -f /var/lib/vta/.bootstrapped && echo yes' || true)" ]]; then
    # PNM phase 1: an admin did:key, pending (`pnm setup --name`). The JSON
    # line is the only thing on stdout.
    PNM_ADMIN="$(tools_sh "pnm setup --name '${PNM_SLUG}' --overwrite 2>/dev/null | jq -r .admin_did" | tr -d '\r')"
    [[ "${PNM_ADMIN}" == did:key:* ]] || die "pnm setup --name did not return an admin DID"
    note "pnm admin DID (temporary; rotates on first use): ${PNM_ADMIN}"
    vta_offline import-did --did "${PNM_ADMIN}" --role admin --label "pnm (bootstrap)"
    in_vta_vol 'touch /var/lib/vta/.bootstrapped'
fi
dc up -d vta
wait_healthy vta
if [[ ! -f "${STATE}/.pnm-complete" ]]; then
    pnm setup continue "${PNM_SLUG}" --vta-did "${VTA_DID}"
    touch "${STATE}/.pnm-complete"
fi
pnm health >/dev/null 2>&1 || pnm health || die "pnm cannot reach the VTA"
note "pnm is the VTA's administrator (slug ${PNM_SLUG})"

# ---------------------------------------------------------------------------
say "3/5 DID hosting for persona DIDs"
if [[ ! -f "${STATE}/.didhost-acl-done" ]]; then
    dc stop did-hosting
    didhost_offline add-acl --did "${VTA_DID}" --role owner --label "research VTA"
    dc up -d did-hosting
    wait_healthy did-hosting
    touch "${STATE}/.didhost-acl-done"
fi
if ! pnm did-mgmt servers list 2>/dev/null | grep -q "${DID_HOST_ID}"; then
    pnm did-mgmt servers add --id "${DID_HOST_ID}" --did "${DID_HOST_DID}" --label "research DID host"
fi
note "the VTA publishes persona DIDs on ${DID_HOST_ID} (${DID_HOST_DID})"

# ---------------------------------------------------------------------------
say "4/5 VTC"
if [[ -z "$(in_vtc_vol 'test -f /var/lib/vtc/config.toml && echo yes' || true)" ]]; then
    if [[ -z "$(in_vtc_vol 'test -f /var/lib/vtc/setup-key.json && echo yes' || true)" ]]; then
        dc run --rm --no-deps -T --entrypoint vtc vtc setup \
            --setup-key-out /var/lib/vtc/setup-key.json --context "${VTC_CONTEXT}" \
            > "${STATE}/vtc-setup-phase1.log" 2>&1 || { cat "${STATE}/vtc-setup-phase1.log" >&2; die "vtc setup phase 1 failed"; }
    fi
    SETUP_DID="$(grep -o 'did:key:z[1-9A-HJ-NP-Za-km-z]*' "${STATE}/vtc-setup-phase1.log" | head -n1)"
    [[ -n "${SETUP_DID}" ]] || die "no setup DID in ${STATE}/vtc-setup-phase1.log"
    note "VTC setup DID: ${SETUP_DID}; granting it at the VTA (one-time hand-off)"
    pnm contexts create --id "${VTC_CONTEXT}" --name "${VTC_NAME}" \
        --admin-did "${SETUP_DID}" --admin-expires 1h --admin-handoff \
      || pnm acl create --did "${SETUP_DID}" --role admin --contexts "${VTC_CONTEXT}" --expires 1h --handoff
    render "${INFRA}/config/vtc-setup.toml.tmpl" "${STATE}/vtc-setup.toml"
    note "vtc setup --from (VTA mints the community DID and keys)"
    dc run --rm --no-deps -T --entrypoint vtc vtc setup --from /state/vtc-setup.toml \
        > "${STATE}/vtc-setup-phase2.log" 2>&1 || { cat "${STATE}/vtc-setup-phase2.log" >&2; die "vtc setup phase 2 failed"; }
fi
VTC_DID="$(toml_get in_vtc_vol /var/lib/vtc/config.toml vtc_did)"
[[ "${VTC_DID}" == did:* ]] || die "could not read vtc_did from the VTC config"
note "community (VTC) DID: ${VTC_DID}"

if [[ -z "$(in_vtc_vol 'test -f /var/lib/vtc/.bootstrapped && echo yes' || true)" ]]; then
    # The setup's own admin key (never printed by setup): keep a copy.
    admin_key_file="$(sed -n 's/^admin_key_file=//p' "${STATE}/vtc-setup-phase2.log" | head -n1 | tr -d '\r')"
    if [[ -n "${admin_key_file}" ]]; then
        in_vtc_vol "cat '${admin_key_file}'" > "${STATE}/vtc-setup-admin-key.json"
        chmod 600 "${STATE}/vtc-setup-admin-key.json"
    fi
    # Path B of vti/docs/03-vtc/bootstrap-runbook.md: offline admin entries.
    # (a) an automation did:key, credential (base64url CredentialBundle) on stdout
    vtc_offline create-did-key --admin --label "automation (bootstrap.sh)" \
        > "${STATE}/vtc-automation.credential" 2> "${STATE}/vtc-automation.log"
    chmod 600 "${STATE}/vtc-automation.credential"
    # (b) the cnm profile's own did:key
    CNM_ADMIN="$(tools_sh "cnm community add '${VTC_NAME}' --vtc-did '${VTC_DID}' 2>/dev/null | jq -r .admin_did" | tr -d '\r')"
    [[ "${CNM_ADMIN}" == did:key:* ]] || die "cnm community add did not return an admin DID"
    vtc_offline acl add --did "${CNM_ADMIN}" --role admin --label "cnm (bootstrap.sh)"
    # (c) a passkey invitation for the human administrator (console), 24h
    vtc_offline admin invite --ttl 86400 > "${STATE}/vtc-admin-invite.txt" 2>&1 \
        || vtc_offline admin invite > "${STATE}/vtc-admin-invite.txt" 2>&1
    in_vtc_vol 'touch /var/lib/vtc/.bootstrapped'
fi
dc up -d vtc
wait_healthy vtc
cnm community continue "${CNM_SLUG}" >/dev/null 2>&1 || note "(cnm community continue: already complete, or see: ./bin/cnm community list)"

# ---------------------------------------------------------------------------
say "5/5 done"
cat > "${STATE}/stack.env" <<EOF
# Written by bootstrap.sh. Source it: set -a; . infra/.state/stack.env; set +a
MEDIATOR_DID=${MEDIATOR_DID}
DID_HOST_DID=${DID_HOST_DID}
VTA_DID=${VTA_DID}
VTC_DID=${VTC_DID}
VTA_URL=http://localhost:8100
VTC_URL=http://localhost:8200
VTA_ALLOW_PRIVATE_ENDPOINTS=1
EOF
cat >&2 <<EOF

  mediator     http://localhost:7037/mediator/v1/   ${MEDIATOR_DID:0:40}…
  did hosting  http://localhost:8534/               ${DID_HOST_DID}
  VTA          http://localhost:8100/               ${VTA_DID}
  VTC          http://localhost:8200/               ${VTC_DID}

  DIDs:                     ${STATE}/stack.env
  VTA admin:                ./bin/pnm …   (e.g. ./bin/pnm acl list)
  VTC admin (CLI):          ./bin/cnm …   (e.g. ./bin/cnm vetting vetters list)
  VTC automation key:       ${STATE}/vtc-automation.credential
  Console admin invitation: ${STATE}/vtc-admin-invite.txt
      open the URL in a browser, enter the claim code, register a passkey.
      You need the console (passkey step-up) to add join criteria and to
      turn hidden vetting on — see README.md §4.

EOF
grep -Ei 'https?://[^ ]*(install|invite|token)[^ ]*|claim' "${STATE}/vtc-admin-invite.txt" >&2 || cat "${STATE}/vtc-admin-invite.txt" >&2
