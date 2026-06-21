[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release', 'Sandbox')]
    [string]$Configuration = 'Release',

    [string]$Image = 'treehammock:api',

    [switch]$NoCache,

    [ValidateSet('auto', 'plain', 'tty')]
    [string]$Progress = 'auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


function Invoke-DockerPullWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Image,
        [int]$Attempts = 3
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        Write-Host "Pulling Docker image $Image (attempt $attempt of $Attempts)..."
        & docker pull $Image
        if ($LASTEXITCODE -eq 0) {
            return
        }

        if ($attempt -lt $Attempts) {
            Start-Sleep -Seconds ([Math]::Min(30, 5 * $attempt))
        }
    }

    throw "Unable to pull Docker image '$Image' after $Attempts attempts. Check Docker Desktop network access, proxy/firewall settings, and registry availability."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker is required to build the API runtime image.'
}

& ./eng/check-locks.ps1

$requiredImages = @(
    'mcr.microsoft.com/dotnet/sdk:8.0',
    'mcr.microsoft.com/dotnet/aspnet:8.0'
)

foreach ($image in $requiredImages) {
    Invoke-DockerPullWithRetry -Image $image
}

$buildArgs = @(
    'build',
    '--target', 'api',
    '--build-arg', "BUILD_CONFIGURATION=$Configuration",
    '--progress', $Progress,
    '-t', $Image
)

if ($NoCache) {
    $buildArgs += '--no-cache'
}

$buildArgs += '.'

& docker @buildArgs
