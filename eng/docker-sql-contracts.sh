#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the SQL contract test Compose lane." >&2
  exit 127
fi

./eng/check-locks.sh

treehammock_pull_with_retry "$TREEHAMMOCK_DOTNET_SDK_IMAGE"

docker compose \
  -f docker-compose.integration.yml \
  --profile sql \
  run --rm --build "$@" sql-contract-tests
