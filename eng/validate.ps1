[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release',

    [switch] $LockedRestore,

    [switch] $CollectCoverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

dotnet --info

$restoreArgs = @('restore', 'treehammock.sln', '--use-lock-file')
if ($LockedRestore) {
    & ./eng/check-locks.ps1
    $restoreArgs += '--locked-mode'
}

dotnet @restoreArgs
dotnet build treehammock.sln --configuration $Configuration --no-restore -p:ContinuousIntegrationBuild=true

$unitArgs = @(
    'test',
    'treehammock.Tests/treehammock.Tests.csproj',
    '--configuration', $Configuration,
    '--no-build',
    '--no-restore',
    '--filter', 'FullyQualifiedName~treehammock.Tests.Unit',
    '--logger', 'trx;LogFileName=treehammock-unit-tests.trx'
)

$integrationArgs = @(
    'test',
    'treehammock.Tests/treehammock.Tests.csproj',
    '--configuration', $Configuration,
    '--no-build',
    '--no-restore',
    '--filter', 'FullyQualifiedName~treehammock.Tests.Integration',
    '--logger', 'trx;LogFileName=treehammock-integration-tests.trx'
)

if ($CollectCoverage) {
    $unitArgs += @('--collect', 'XPlat Code Coverage')
    $integrationArgs += @('--collect', 'XPlat Code Coverage')
}

dotnet @unitArgs
dotnet @integrationArgs
