[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string] $Configuration = 'Release',

    [switch] $RefreshLocks,
    [switch] $RequireLocks,
    [switch] $LockedRestore,
    [switch] $RunSqlContracts,
    [switch] $CollectCoverage
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'The .NET SDK is required to prove this build. Install .NET 8 and rerun ./eng/build-proof.ps1.'
}

dotnet --info

if ($RefreshLocks) {
    & ./eng/restore-locks.ps1
}

if ($RequireLocks -or $LockedRestore) {
    & ./eng/check-locks.ps1
}

& ./eng/validate.ps1 -Configuration $Configuration -LockedRestore:$LockedRestore -CollectCoverage:$CollectCoverage

if ($RunSqlContracts) {
    & ./eng/sql-contracts.ps1 -Configuration $Configuration -LockedRestore:$LockedRestore
}
