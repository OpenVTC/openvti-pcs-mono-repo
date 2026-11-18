#!/usr/bin/env bash
# Stop the stack and DELETE all of its state: every volume (keys, DIDs,
# stores, CLI sessions) and infra/.state. Images are kept.
set -euo pipefail
INFRA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker compose -f "${INFRA}/docker-compose.yml" --profile tools down -v --remove-orphans
rm -rf "${INFRA}/.state"
echo "stack removed; run ./bootstrap.sh to start again"
