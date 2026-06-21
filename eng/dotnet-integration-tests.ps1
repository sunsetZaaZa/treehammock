[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [switch]$LockedRestore,
    [switch]$CollectCoverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $RepoRoot

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "The .NET SDK is required to run the integration-test lane."
}

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

$restoreArgs = @('restore', 'treehammock.sln', '--use-lock-file')
if ($LockedRestore) {
    & ./eng/check-locks.ps1
    $restoreArgs += '--locked-mode'
}

& dotnet @restoreArgs
& dotnet build treehammock.sln --configuration $Configuration --no-restore -p:ContinuousIntegrationBuild=true

$testArgs = @(
    'test',
    'treehammock.Tests/treehammock.Tests.csproj',
    '--configuration', $Configuration,
    '--no-build',
    '--no-restore',
    '--filter', 'FullyQualifiedName~treehammock.Tests.Integration',
    '--logger', 'trx;LogFileName=treehammock-integration-tests.trx'
)

if ($CollectCoverage) {
    $testArgs += @('--collect', 'XPlat Code Coverage')
}

& dotnet @testArgs
