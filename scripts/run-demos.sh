#!/usr/bin/env bash
# Run the vetting demos, in process: no Docker, no network services.
#
#   ./scripts/run-demos.sh            # all of them, in order
#   ./scripts/run-demos.sh pcs        # one of: pcs, prototype, engines, peer, hidden
#
# Each demo is a test suite; the comment at the top of each test file walks
# through the flow it runs.
set -euo pipefail
cd "$(dirname "$0")/.."

run() {
  local title=$1; shift
  printf '\n\033[1m== %s\033[0m\n$ %s\n' "$title" "$*"
  "$@"
}

pcs() {
  run "1. PCS: the pcreds protocol (issuance by threshold, membership proofs, object sizes)" \
    cargo test --release -p predicate-credential-system --test pcreds
}
prototype() {
  run "2. PCS: hidden-vetter admission prototype (VTC, vetters, applicant in memory)" \
    cargo test --release -p pcs-vetting-prototype
}
engines() {
  run "3. VTI: the hidden-vetting engines the VTA and VTC run, end to end" \
    cargo test --release -p vti-vetting-pcs --test end_to_end
}
peer() {
  run "4. OpenVTC: peer vetting ceremony over a real in-process DIDComm mediator" \
    cargo test -p openvtc-core --test vetting_e2e -- --include-ignored
}
hidden() {
  run "5. OpenVTC: onboarding under hidden vetting, every PCS key held by a real in-process VTA" \
    cargo test -p openvtc-core --test hidden_vetting_onboarding -- --include-ignored
}

if [ $# -eq 0 ]; then
  pcs; prototype; engines; peer; hidden
else
  for d in "$@"; do "$d"; done
fi
printf '\n\033[1mAll requested demos passed.\033[0m\n'
