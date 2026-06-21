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
    throw 'Docker is required to run the SQL contract test Compose lane.'
}

& ./eng/check-locks.ps1

& docker compose `
    -f docker-compose.integration.yml `
    --profile sql `
    run --rm --build @ComposeArgs sql-contract-tests
