[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release',

    [switch] $LockedRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$treehammockRunDeferredSqlContracts = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS', 'Process')
$treehammockDbContractConnection = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_DB_CONTRACT_CONNECTION', 'Process')

if ($treehammockRunDeferredSqlContracts -ne 'true' -and $treehammockRunDeferredSqlContracts -ne '1') {
    throw 'TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS must be true or 1 to run SQL contract tests.'
}

if ([string]::IsNullOrWhiteSpace($treehammockDbContractConnection)) {
    throw 'TREEHAMMOCK_DB_CONTRACT_CONNECTION must point to a disposable PostgreSQL database.'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

$env:DOTNET_NOLOGO = 'true'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = 'true'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE = 'true'

dotnet --info

$restoreArgs = @('restore', 'eng/treehammock.SqlContracts.sln', '--use-lock-file')
if ($LockedRestore) {
    & ./eng/check-locks.ps1
    $restoreArgs += '--locked-mode'
}

dotnet @restoreArgs
dotnet build eng/treehammock.SqlContracts.sln --configuration $Configuration --no-restore -p:ContinuousIntegrationBuild=true
dotnet test treehammock.Tests.SqlContracts/treehammock.Tests.SqlContracts.csproj --configuration $Configuration --no-build --no-restore --logger 'trx;LogFileName=treehammock-sql-contracts.trx'
