[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string]$Configuration = 'Release',

    [string]$Image = 'treehammock:unit-test',

    [switch]$NoCache,

    [ValidateSet('auto', 'plain', 'tty')]
    [string]$Progress = 'auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to run the containerized unit-test lane.'
}

& ./eng/check-locks.ps1

$buildArgs = @(
    'build',
    '--target', 'unit-test',
    '--build-arg', "BUILD_CONFIGURATION=$Configuration",
    '--progress', $Progress,
    '-t', $Image
)

if ($NoCache) {
    $buildArgs += '--no-cache'
}

$buildArgs += '.'

& docker @buildArgs
