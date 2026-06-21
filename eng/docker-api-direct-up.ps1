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
    throw 'Docker is required to run the API Compose stack.'
}

& ./eng/check-locks.ps1

& docker compose `
    -f docker-compose.integration.yml `
    -f docker-compose.api-direct.yml `
    up --build @ComposeArgs postgres dragonfly api
