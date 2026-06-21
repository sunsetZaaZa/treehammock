#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# shellcheck source=eng/docker-cli.sh
source ./eng/docker-cli.sh

wait_for_system_readiness() {
  local url="${1:-http://localhost:8080/health/ready}"
  local timeout_seconds="${2:-120}"
  local deadline=$((SECONDS + timeout_seconds))
  local last_error=""

  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl --fail --silent --show-error --max-time 5 "$url" >/dev/null 2> .artifacts/system-host-readiness.err; then
      rm -f .artifacts/system-host-readiness.err
      return 0
    fi

    last_error="$(cat .artifacts/system-host-readiness.err 2>/dev/null || true)"
    sleep 2
  done

  echo "Timed out waiting for ${url} to become ready. Last error: ${last_error}" >&2
  return 1
}

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI is required to run the host-backed system stack test lane. Install Docker Desktop or Docker Engine, then retry." >&2
  exit 127
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo ".NET SDK is required to run the backend and system tests on the host." >&2
  exit 127
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but the Docker daemon is not reachable. Start Docker Desktop or the Docker service, wait until Docker is running, then retry ./eng/docker-host-system-stack-tests.sh." >&2
  exit 1
fi

./eng/check-locks.sh

for image in \
  "postgres:16" \
  "docker.dragonflydb.io/dragonflydb/dragonfly:latest" \
  "haproxy:latest"; do
  treehammock_pull_with_retry "$image"
done

mkdir -p .artifacts
compose=(docker compose -f docker-compose.local-system.yml --profile host-system)
"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up -d "$@" postgres dragonfly haproxy-host

api_pid=""
cleanup() {
  if [ -n "$api_pid" ] && kill -0 "$api_pid" >/dev/null 2>&1; then
    kill "$api_pid" >/dev/null 2>&1 || true
    wait "$api_pid" >/dev/null 2>&1 || true
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

export ASPNETCORE_ENVIRONMENT=ContainerReverseProxy
export DOTNET_ENVIRONMENT=ContainerReverseProxy
export ASPNETCORE_URLS=http://0.0.0.0:5001

export DatabaseSettings__servers=127.0.0.1
export DatabaseSettings__database=treehammock
export DatabaseSettings__userId=treehammock
export DatabaseSettings__password=treehammock-password
export DatabaseSettings__lc_collation=en_US.UTF-8

export ActiveUserBundleSettings__servers=127.0.0.1
export ActiveUserBundleSettings__port=6379
export ActiveUserBundleSettings__database=0
export ActiveUserBundleSettings__clientName=treehammock-api-host
export ActiveUserBundleSettings__allowAdmin=false
export ActiveUserBundleSettings__reconnectRetryPolicy=5000
export ActiveUserBundleSettings__abortOnConnectFail=false
export ActiveUserBundleSettings__password=

export TwoFactorSessionBundleSettings__servers=127.0.0.1
export TwoFactorSessionBundleSettings__port=6379
export TwoFactorSessionBundleSettings__database=1
export TwoFactorSessionBundleSettings__clientName=treehammock-api-host-2fa
export TwoFactorSessionBundleSettings__allowAdmin=false
export TwoFactorSessionBundleSettings__reconnectRetryPolicy=5000
export TwoFactorSessionBundleSettings__abortOnConnectFail=false
export TwoFactorSessionBundleSettings__password=

export AbuseCounterBundleSettings__servers=127.0.0.1
export AbuseCounterBundleSettings__port=6379
export AbuseCounterBundleSettings__database=2
export AbuseCounterBundleSettings__clientName=treehammock-api-host-abuse-counters
export AbuseCounterBundleSettings__allowAdmin=false
export AbuseCounterBundleSettings__reconnectRetryPolicy=5000
export AbuseCounterBundleSettings__abortOnConnectFail=false
export AbuseCounterBundleSettings__password=

# The host-backed system lane exercises many happy-path flows from one loopback IP.
# Keep production abuse controls enabled, but raise shared-IP test ceilings so
# unrelated end-to-end scenarios do not trip each other's delivery throttles.
export AbuseControlSettings__Delivery__MaxEmailDeliveriesPerAccountPerHour=100
export AbuseControlSettings__Delivery__MaxSmsDeliveriesPerAccountPerHour=100
export AbuseControlSettings__Delivery__MaxEmailDeliveriesPerIpPerHour=100
export AbuseControlSettings__Delivery__MaxSmsDeliveriesPerIpPerHour=100
export AbuseControlSettings__PasswordReset__MaxRequestsPerAccountPerHour=100
export AbuseControlSettings__PasswordReset__MaxRequestsPerIdentifierPerHour=100
export AbuseControlSettings__PasswordReset__MaxRequestsPerIpPerHour=100
export PasswordResetSettings__RequestCooldownSeconds=0
export PasswordResetSettings__DailyRequestLimitPerAccount=100
export PasswordResetSettings__DailyRequestLimitPerDestination=100
export PasswordResetSettings__DailyRequestLimitPerIp=100

export HostingSettings__ConfigureKestrel=true
export HostingSettings__Port=5001
export HostingSettings__BindAddress=0.0.0.0
export HostingSettings__UseHttps=false
export HostingSettings__Protocols=Http1AndHttp2
export HostingSettings__UseHttpsRedirection=false
export HostingSettings__UseForwardedHeaders=true
export HostingSettings__ForwardLimit=1
export HostingSettings__RequireHeaderSymmetry=true
export HostingSettings__TrustAllForwardedHeaderProxies=true
export SystemTestSettings__Enabled=true
export SystemTestSettings__EnableTestInspectionEndpoints=true
export SystemTestSettings__TestKey=treehammock-system-test-key
export SystemTestSettings__DeliveryCaptureConnection="Host=127.0.0.1;Port=5432;Database=treehammock;Username=treehammock;Password=treehammock-password"
export TREEHAMMOCK_SYSTEM_BASE_URL=http://localhost:8080
export TREEHAMMOCK_SYSTEM_TEST_KEY=treehammock-system-test-key

dotnet restore treehammock.Tests.System/treehammock.Tests.System.csproj --locked-mode

dotnet run --project treehammock.csproj --configuration Release --no-restore --urls http://0.0.0.0:5001 > .artifacts/system-host-api.out.log 2> .artifacts/system-host-api.err.log &
api_pid="$!"

wait_for_system_readiness

if ! dotnet test treehammock.Tests.System/treehammock.Tests.System.csproj --no-restore --logger "trx;LogFileName=treehammock-system-host-tests.trx"; then
  echo
  echo "System host API stdout (.artifacts/system-host-api.out.log):"
  tail -200 .artifacts/system-host-api.out.log 2>/dev/null || true
  echo
  echo "System host API stderr (.artifacts/system-host-api.err.log):"
  tail -200 .artifacts/system-host-api.err.log 2>/dev/null || true
  exit 1
fi
