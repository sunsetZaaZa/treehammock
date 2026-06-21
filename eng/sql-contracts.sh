#!/usr/bin/env bash
set -euo pipefail

configuration="Release"
locked_restore="false"

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
    -h|--help)
      cat <<'USAGE'
Usage: ./eng/sql-contracts.sh [--configuration Release|Debug|Sandbox] [--locked-restore]

Runs the dedicated PostgreSQL SQL contract test suite. Requires:
  TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS=true
  TREEHAMMOCK_DB_CONTRACT_CONNECTION="Host=...;Database=...;Username=...;Password=..."
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS:-}" != "true" && "${TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS:-}" != "1" ]]; then
  echo "TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS must be true or 1 to run SQL contract tests." >&2
  exit 2
fi

if [[ -z "${TREEHAMMOCK_DB_CONTRACT_CONNECTION:-}" ]]; then
  echo "TREEHAMMOCK_DB_CONTRACT_CONNECTION must point to a disposable PostgreSQL database." >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export DOTNET_NOLOGO=true
export DOTNET_CLI_TELEMETRY_OPTOUT=true
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true

dotnet --info

restore_args=(restore eng/treehammock.SqlContracts.sln --use-lock-file)
if [[ "$locked_restore" == "true" ]]; then
  ./eng/check-locks.sh
  restore_args+=(--locked-mode)
fi

dotnet "${restore_args[@]}"
dotnet build eng/treehammock.SqlContracts.sln --configuration "$configuration" --no-restore -p:ContinuousIntegrationBuild=true
dotnet test treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj --configuration "$configuration" --no-build --no-restore --logger "trx;LogFileName=treehammock-sql-contracts.trx"
