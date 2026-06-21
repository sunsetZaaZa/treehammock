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
    throw 'Docker is required to run the direct HTTP contract test Compose lane.'
}

& ./eng/check-locks.ps1

& docker compose `
    -f docker-compose.integration.yml `
    --profile http `
    run --rm --build @ComposeArgs http-contract-tests-direct
