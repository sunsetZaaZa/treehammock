[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$treehammockRunDeferredSqlContracts = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS', 'Process')
$treehammockDbContractConnection = [Environment]::GetEnvironmentVariable('TREEHAMMOCK_DB_CONTRACT_CONNECTION', 'Process')

if ($treehammockRunDeferredSqlContracts -ne 'true' -and $treehammockRunDeferredSqlContracts -ne '1') {
    throw 'TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS must be true or 1 for the final release gate.'
}

if ([string]::IsNullOrWhiteSpace($treehammockDbContractConnection)) {
    throw 'TREEHAMMOCK_DB_CONTRACT_CONNECTION must point to a disposable PostgreSQL database for the final release gate.'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

& ./eng/build-proof.ps1 -Configuration $Configuration -LockedRestore -RunSqlContracts
