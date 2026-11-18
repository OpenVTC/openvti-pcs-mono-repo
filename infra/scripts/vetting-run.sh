#!/usr/bin/env bash
# A complete vetting run against the local stack, with no human in the loop.
#
#   infra/scripts/vetting-run.sh [peer|hidden|all]     (default: all)
#
# People (one OpenVTC profile each, under infra/.state/clients):
#   carol, dave  vetters
#   alice        applicant, peer vetting   (criterion kernel-developer)
#   bob          applicant, hidden vetting (criterion kernel-developer-hidden)
#
# Prerequisites, once (infra/README.md):
#   ./bootstrap.sh                       the stack, provisioned
#   bin/console claim                    the console's admin passkey (virtual)
#   bin/console add-criterion scripts/console/criterion-peer.json
#   bin/console add-criterion scripts/console/criterion-hidden.json
#   bin/console hidden-on kernel-developer-hidden
#   (and the `review` re-ordering the console section of the README describes)
#
# Every client is the real `openvtc` (state handler, VTA session, mediator,
# inbound handling), driven by `openvtc script …` in place of its TUI; build it
# with `cargo build -p openvtc --features scripted`. Each person is a separate
# process; they hand tickets over through infra/.state/exchange-*.
set -euo pipefail
what=${1:-all}
INFRA="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$INFRA/.." && pwd)"
STATE="$INFRA/.state"
OPENVTC=${OPENVTC:-$ROOT/target/debug/openvtc}
LOGS="$STATE/client-logs"
mkdir -p "$LOGS"
set -a; . "$STATE/stack.env"; set +a
export OPENVTC_CONFIG_PATH="$STATE/clients" OPENVTC_SECURE_STORE=file VTA_ALLOW_PRIVATE_ENDPOINTS=1

say() { printf '\n\033[1m### %s\033[0m\n' "$*"; }
ovt() { local who=$1; shift
  OPENVTC_DEBUG_LOG="$LOGS/$who-trace.log" "$OPENVTC" -p "$who" \
    --unlock-code-file "$STATE/clients/$who.unlock" "$@"; }

[ -x "$OPENVTC" ] || { echo "build the client first: cargo build -p openvtc --features scripted" >&2; exit 1; }

# 1. Profiles.
for who in carol dave alice bob; do
  if [ ! -f "$STATE/clients/config-$who.json" ]; then
    say "profile $who"
    "$INFRA/scripts/client-setup.sh" "$who"
  fi
done

# 2. Vetters: members, then named vetters. A join is an open request the
#    administrator approves (bin/console approve-join) while the client waits.
vetter_persona() { grep -oE 'persona created: \S+' "$LOGS/$1-join.log" 2>/dev/null | awk '{print $3}' | tail -1; }
for who in carol dave; do
  marker="$STATE/clients/.$who-vetter"
  [ -f "$marker" ] && continue
  say "$who joins the community"
  ( ovt "$who" community join "$VTC_DID" --new-persona "$who-vetter" --wait 30m \
      >"$LOGS/$who-join.log" 2>&1; echo "exit=$?" >>"$LOGS/$who-join.log" ) &
  until grep -qE 'acknowledged the request|^exit=' "$LOGS/$who-join.log" 2>/dev/null; do sleep 2; done
  persona=$(vetter_persona "$who")
  [ -n "$persona" ] || { cat "$LOGS/$who-join.log"; exit 1; }
  say "administrator approves $who ($persona)"
  "$INFRA/bin/console" approve-join "$persona" | grep -E '"state"'
  until grep -q '^exit=' "$LOGS/$who-join.log"; do sleep 3; done
  grep -q '^exit=0' "$LOGS/$who-join.log" || { tail -20 "$LOGS/$who-join.log"; exit 1; }
  # Named a vetter in run_flow, while the client is connected.
  echo "$persona" >"$marker"
done

run_flow() { # name applicant criterion-flag
  local flow=$1 applicant=$2 flag=${3:-}
  local ex="$STATE/exchange-$flow"
  rm -rf "$ex"; mkdir -p "$ex"
  say "$flow vetting: carol and dave at their desks, $applicant applying"
  local pids=()
  for v in carol dave; do
    ovt "$v" script vetter --exchange "$ex" --community "$VTC_DID" --name "$v" \
      --sessions 1 --timeout "${STEP_TIMEOUT:-600}" $flag >"$LOGS/$flow-$v.log" 2>&1 & pids+=($!)
  done
  # Name the vetters while their clients are connected, so the grant (pushed
  # over DIDComm) arrives live. Re-granting also makes the run repeatable.
  for v in carol dave; do
    until grep -q '^== ' "$LOGS/$flow-$v.log" 2>/dev/null; do sleep 2; done
  done
  sleep 15
  for v in carol dave; do
    persona=$(cat "$STATE/clients/.$v-vetter")
    for id in $("$INFRA/bin/cnm" vetting vetters list 2>/dev/null | sed -n '/^\[/,$p' |
        jq -r --arg d "$persona" '.[] | select(.memberDid == $d and .live) | .endorsementId'); do
      "$INFRA/bin/cnm" vetting vetters revoke "$id" >/dev/null 2>&1 || true
    done
    "$INFRA/bin/cnm" vetting vetters grant "$persona" --validity 365d >/dev/null 2>&1
    echo "   $v named a vetter ($persona)"
  done
  ovt "$applicant" script applicant --exchange "$ex" --community "$VTC_DID" \
    --vetters carol dave --timeout "${STEP_TIMEOUT:-600}" $flag >"$LOGS/$flow-$applicant.log" 2>&1 & pids+=($!)
  local failed=0
  for p in "${pids[@]}"; do wait "$p" || failed=1; done
  for f in "$LOGS/$flow-carol.log" "$LOGS/$flow-dave.log" "$LOGS/$flow-$applicant.log"; do
    echo "--- $(basename "$f")"; grep -E '^== |ticket:|card from|statement|admitted|Error|error:' "$f" || true
  done
  [ $failed -eq 0 ] || { say "$flow vetting FAILED (logs in $LOGS)"; return 1; }
  say "$flow vetting: $applicant admitted"
}

# A vetter's client reads a community that hides any criterion's vetters as
# hiding them all (PCS ZKP mode: tokens before tickets), so named vetting runs
# with no hidden criterion, and hidden vetting adds one.
peer_setup() {
  say "community: named vetting only (kernel-developer)"
  "$INFRA/bin/console" remove-criterion kernel-developer-hidden >/dev/null 2>&1 || true
}
hidden_setup() {
  say "community: hidden vetting on (kernel-developer-hidden)"
  "$INFRA/bin/console" add-criterion "$INFRA/scripts/console/criterion-hidden.json" >/dev/null
  "$INFRA/bin/console" hidden-on kernel-developer-hidden | tail -5
}

case $what in
  peer)   peer_setup && run_flow peer alice ;;
  hidden) hidden_setup && run_flow hidden bob --hidden ;;
  all)    peer_setup && run_flow peer alice && hidden_setup && run_flow hidden bob --hidden ;;
  *) echo "usage: $0 [peer|hidden|all]" >&2; exit 2 ;;
esac
