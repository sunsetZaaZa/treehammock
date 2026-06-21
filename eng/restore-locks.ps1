[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'The .NET SDK is required to refresh package lock files. Install .NET 8 and rerun ./eng/restore-locks.ps1.'
}

dotnet restore treehammock.sln --use-lock-file --force-evaluate
dotnet restore eng/treehammock.SqlContracts.sln --use-lock-file --force-evaluate
dotnet restore treehammock.Tests.System/treehammock.Tests.System.csproj --use-lock-file --force-evaluate
& ./eng/check-locks.ps1

Write-Host ''
if (Get-Command git -ErrorAction SilentlyContinue) {
    Write-Host 'Review and commit generated lock files:'
    git status --short -- '**/packages.lock.json' Directory.Packages.props '**/*.csproj'
} else {
    Write-Host 'dotnet restore completed. Review generated packages.lock.json files before committing.'
}
