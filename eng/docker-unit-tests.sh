#!/usr/bin/env bash
set -euo pipefail

configuration="Release"
image_name="treehammock:unit-test"
no_cache="false"
progress="auto"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --configuration)
      configuration="${2:?Missing value for --configuration}"
      shift 2
      ;;
    --image)
      image_name="${2:?Missing value for --image}"
      shift 2
      ;;
    --no-cache)
      no_cache="true"
      shift
      ;;
    --progress)
      progress="${2:?Missing value for --progress}"
      shift 2
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/docker-unit-tests.sh [--configuration Release|Debug|Sandbox] [--image name:tag] [--no-cache] [--progress auto|plain|tty]

Builds the Docker unit-test target. The Dockerfile performs a locked NuGet
restore, builds the solution, and runs only the treehammock.Tests.Unit namespace.
In-process .NET integration tests are run by ./eng/dotnet-integration-tests.sh.
Real PostgreSQL SQL contracts are run by the sql-contract-tests profile.

Before running this command for the first time, generate and commit package
lock files:
  ./eng/restore-locks.sh
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run the containerized unit-test lane." >&2
  exit 127
fi

./eng/check-locks.sh

treehammock_pull_with_retry "$TREEHAMMOCK_DOTNET_SDK_IMAGE"

build_args=(
  build
  --target unit-test
  --build-arg "DOTNET_SDK_IMAGE=${TREEHAMMOCK_DOTNET_SDK_IMAGE}"
  --build-arg "DOTNET_RUNTIME_IMAGE=${TREEHAMMOCK_DOTNET_RUNTIME_IMAGE}"
  --build-arg "BUILD_CONFIGURATION=$configuration"
  --progress "$progress"
  -t "$image_name"
)

if [[ "$no_cache" == "true" ]]; then
  build_args+=(--no-cache)
fi

build_args+=(.)

docker "${build_args[@]}"
