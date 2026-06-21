[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the full Docker runtime stack.'
}

& ./eng/check-locks.ps1

# Full runtime mode means every long-running service used by local integration:
# PostgreSQL + DragonflyDB + API + HAProxy. Test runners remain explicit one-shot lanes.
& docker compose `
    -f docker-compose.integration.yml `
    -f docker-compose.api-proxy.yml `
    --profile proxy `
    up --build @ComposeArgs postgres dragonfly api haproxy
