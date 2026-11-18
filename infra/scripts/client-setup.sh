#!/usr/bin/env bash
# Create an OpenVTC profile against the stack's VTA, with no human in the loop:
# run headless `openvtc setup`, read the `pnm` grant it asks the VTA admin for,
# make that grant with ./bin/pnm, and wait for setup to finish.
#
#   infra/scripts/client-setup.sh <name>
#
# Uses $OPENVTC (default: target/debug/openvtc built with `--features scripted`)
# and keeps profiles under infra/.state/clients (OPENVTC_CONFIG_PATH), with keys
# in the client's encrypted-file store (OPENVTC_SECURE_STORE=file).
set -euo pipefail
name=${1:?usage: client-setup.sh <name>}
INFRA="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$INFRA/.." && pwd)"
OPENVTC=${OPENVTC:-$ROOT/target/debug/openvtc}
STATE="$INFRA/.state"
set -a; . "$STATE/stack.env"; set +a
export OPENVTC_CONFIG_PATH="$STATE/clients" OPENVTC_SECURE_STORE=file VTA_ALLOW_PRIVATE_ENDPOINTS=1
mkdir -p "$OPENVTC_CONFIG_PATH" "$STATE/client-logs"

unlock="$STATE/clients/$name.unlock"
[ -f "$unlock" ] || { printf 'research-%s-%s\n' "$name" "$(openssl rand -hex 8)" > "$unlock"; chmod 600 "$unlock"; }

log="$STATE/client-logs/$name-setup.log"
: > "$log"
"$OPENVTC" -p "$name" setup --vta-did "$VTA_DID" --unlock-code-file "$unlock" \
  --context "openvtc-$name" --wait 5m >"$log" 2>&1 &
pid=$!

# The grant command setup prints, joined from its continuation lines.
grant=""
for _ in $(seq 1 120); do
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  grant=$(awk '/^pnm contexts create/{p=1} p{print} p&&!/\\$/{exit}' "$log" | tr -d '\\\n')
  [ -n "$grant" ] && break
  sleep 1
done
[ -n "$grant" ] || { cat "$log"; echo "setup for $name printed no grant" >&2; exit 1; }
echo "[$name] granting: ${grant#pnm }"
# shellcheck disable=SC2086
# `pnm contexts create` exits 0 when the context already exists, saying the
# admin DID was NOT added; that is the case for the fallback below.
out=$(eval "\"$INFRA/bin/pnm\" ${grant#pnm }" 2>&1) || true
if ! grep -q 'Hand-off:' <<<"$out"; then
  # The context exists already (a profile re-created): setup prints the grant
  # for that case too.
  alt=$(awk '/^pnm acl create/{p=1} p{print} p&&!/\\$/{exit}' "$log" | tr -d '\\\n')
  echo "[$name] context exists; granting: ${alt#pnm }"
  eval "\"$INFRA/bin/pnm\" ${alt#pnm }" >/dev/null 2>&1 || {
    echo "pnm grant failed for $name" >&2; kill "$pid" 2>/dev/null; exit 1; }
fi
if wait "$pid"; then
  echo "[$name] profile ready"
else
  cat "$log"; echo "setup for $name failed" >&2; exit 1
fi
