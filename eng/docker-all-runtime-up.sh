#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the full Docker runtime stack." >&2
  exit 127
fi

./eng/check-locks.sh

treehammock_pull_dotnet_dockerfile_images
compose_image_override="$(treehammock_write_compose_image_override)"

# Full runtime mode means every long-running service used by local integration:
# PostgreSQL + DragonflyDB + API + HAProxy. Test runners remain explicit one-shot lanes.
docker compose \
  -f docker-compose.integration.yml \
  -f docker-compose.api-proxy.yml \
  -f "$compose_image_override" \
  --profile proxy \
  up --build "$@" postgres dragonfly api haproxy
