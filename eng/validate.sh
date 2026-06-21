#!/usr/bin/env bash
set -euo pipefail

configuration="Release"
locked_restore="false"
collect_coverage="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --configuration)
      configuration="${2:?Missing value for --configuration}"
      shift 2
      ;;
    --locked-restore)
      locked_restore="true"
      shift
      ;;
    --collect-coverage)
      collect_coverage="true"
      shift
      ;;
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/validate.sh [--configuration Release|Debug|Sandbox] [--locked-restore] [--collect-coverage]

Runs the reproducible local/CI fast validation lane:
  1. dotnet restore treehammock.sln --use-lock-file
  2. dotnet build treehammock.sln --no-restore
  3. dotnet test treehammock.Tests for the Unit namespace
  4. dotnet test treehammock.Tests for the in-process Integration namespace

Real PostgreSQL SQL contracts are a separate suite: ./eng/sql-contracts.sh.
Use --locked-restore only after packages.lock.json files have been generated and committed.
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

export DOTNET_NOLOGO=true
export DOTNET_CLI_TELEMETRY_OPTOUT=true
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true

dotnet --info

restore_args=(restore treehammock.sln --use-lock-file)
if [[ "$locked_restore" == "true" ]]; then
  ./eng/check-locks.sh
  restore_args+=(--locked-mode)
fi

dotnet "${restore_args[@]}"
dotnet build treehammock.sln --configuration "$configuration" --no-restore -p:ContinuousIntegrationBuild=true

unit_args=(test treehammock.Tests/treehammock.Tests.csproj --configuration "$configuration" --no-build --no-restore --filter "FullyQualifiedName~treehammock.Tests.Unit" --logger "trx;LogFileName=treehammock-unit-tests.trx")
integration_args=(test treehammock.Tests/treehammock.Tests.csproj --configuration "$configuration" --no-build --no-restore --filter "FullyQualifiedName~treehammock.Tests.Integration" --logger "trx;LogFileName=treehammock-integration-tests.trx")
if [[ "$collect_coverage" == "true" ]]; then
  unit_args+=(--collect "XPlat Code Coverage")
  integration_args+=(--collect "XPlat Code Coverage")
fi

dotnet "${unit_args[@]}"
dotnet "${integration_args[@]}"
