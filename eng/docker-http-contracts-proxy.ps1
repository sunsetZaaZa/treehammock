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
    throw 'Docker is required to run the HAProxy HTTP contract test Compose lane.'
}

& ./eng/check-locks.ps1

& docker compose `
    -f docker-compose.integration.yml `
    -f docker-compose.api-proxy.yml `
    --profile proxy `
    --profile http-proxy `
    run --rm --build @ComposeArgs http-contract-tests-proxy
