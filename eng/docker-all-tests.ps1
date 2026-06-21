[CmdletBinding()]
param(
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if ($Help) {
    @'
Usage: ./eng/docker-all-tests.ps1

Runs all Docker-backed validation lanes in sequence:
  1. Unit tests in the Docker unit-test image
  2. SQL contract suite tests against Compose PostgreSQL
  3. Bruno HTTP checks against the API service directly
  4. Bruno HTTP checks against the HAProxy service
  5. Full Compose system tests through HAProxy

Generate package lock files first:
  ./eng/restore-locks.ps1
'@ | Write-Output
    exit 0
}

& ./eng/docker-unit-tests.ps1
& ./eng/docker-sql-contracts.ps1
& ./eng/docker-http-contracts-direct.ps1
& ./eng/docker-http-contracts-proxy.ps1

& ./eng/docker-system-stack-tests.ps1
