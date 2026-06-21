[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
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

    throw "Unable to pull Docker image '$Image' after $Attempts attempts. Check Docker Desktop network access, VPN/proxy/firewall settings, and registry availability."
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI is required to run the full system stack test lane. Install Docker Desktop or Docker Engine, then retry.'
}

try {
    & docker info *> $null
}
catch {
    throw 'Docker is installed, but the Docker daemon is not reachable. Start Docker Desktop, wait until it says Docker is running, then retry ./eng/docker-system-stack-tests.ps1.'
}

& ./eng/check-locks.ps1

$requiredImages = @(
    'mcr.microsoft.com/dotnet/sdk:8.0',
    'mcr.microsoft.com/dotnet/aspnet:8.0',
    'postgres:16',
    'docker.dragonflydb.io/dragonflydb/dragonfly:latest',
    'haproxy:latest'
)

foreach ($image in $requiredImages) {
    Invoke-DockerPullWithRetry -Image $image
}

& docker compose `
    -f docker-compose.integration.yml `
    -f docker-compose.api-proxy.yml `
    -f docker-compose.ci-system.yml `
    --profile proxy `
    --profile system `
    down --volumes --remove-orphans *> $null

& docker compose `
    -f docker-compose.integration.yml `
    -f docker-compose.api-proxy.yml `
    -f docker-compose.ci-system.yml `
    --profile proxy `
    --profile system `
    up --build --abort-on-container-exit --exit-code-from system-tests @ComposeArgs system-tests
