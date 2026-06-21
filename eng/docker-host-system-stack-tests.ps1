[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# When this script is launched by the companion .cmd runner, the entrypoint runs
# under a process-local execution-policy bypass. Set the same process-local policy
# again here so nested PowerShell scripts, such as ./eng/check-locks.ps1, do not
# prompt for "Run once" when the checkout was downloaded from the internet.
if (-not $PSVersionTable.ContainsKey('Platform') -or $PSVersionTable.Platform -eq 'Win32NT') {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
}

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

function Wait-ForSystemReadiness {
    param(
        [string]$Url = 'http://localhost:8080/health/ready',
        [int]$TimeoutSeconds = 120
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastError = $null

    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            $lastError = $_.Exception.Message
        }

        Start-Sleep -Seconds 2
    }

    throw "Timed out waiting for $Url to become ready. Last error: $lastError"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker CLI is required to run the host-backed system stack test lane. Install Docker Desktop or Docker Engine, then retry.'
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '.NET SDK is required to run the backend and system tests on the host.'
}

try {
    & docker info *> $null
}
catch {
    throw 'Docker is installed, but the Docker daemon is not reachable. Start Docker Desktop, wait until it says Docker is running, then retry ./eng/docker-host-system-stack-tests.ps1.'
}

& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File ./eng/check-locks.ps1

$requiredImages = @(
    'postgres:16',
    'docker.dragonflydb.io/dragonflydb/dragonfly:latest',
    'haproxy:latest'
)

foreach ($image in $requiredImages) {
    Invoke-DockerPullWithRetry -Image $image
}

New-Item -ItemType Directory -Path .artifacts -Force | Out-Null

$composeFiles = @('-f', 'docker-compose.local-system.yml', '--profile', 'host-system')
& docker compose @composeFiles down --volumes --remove-orphans *> $null
& docker compose @composeFiles up -d @ComposeArgs postgres dragonfly haproxy-host

$previousEnvironment = @{}
$environmentKeys = @(
    'ASPNETCORE_ENVIRONMENT',
    'DOTNET_ENVIRONMENT',
    'ASPNETCORE_URLS',
    'DatabaseSettings__servers',
    'DatabaseSettings__database',
    'DatabaseSettings__userId',
    'DatabaseSettings__password',
    'DatabaseSettings__lc_collation',
    'ActiveUserBundleSettings__servers',
    'ActiveUserBundleSettings__port',
    'ActiveUserBundleSettings__database',
    'ActiveUserBundleSettings__clientName',
    'ActiveUserBundleSettings__allowAdmin',
    'ActiveUserBundleSettings__reconnectRetryPolicy',
    'ActiveUserBundleSettings__abortOnConnectFail',
    'ActiveUserBundleSettings__password',
    'TwoFactorSessionBundleSettings__servers',
    'TwoFactorSessionBundleSettings__port',
    'TwoFactorSessionBundleSettings__database',
    'TwoFactorSessionBundleSettings__clientName',
    'TwoFactorSessionBundleSettings__allowAdmin',
    'TwoFactorSessionBundleSettings__reconnectRetryPolicy',
    'TwoFactorSessionBundleSettings__abortOnConnectFail',
    'TwoFactorSessionBundleSettings__password',
    'AbuseCounterBundleSettings__servers',
    'AbuseCounterBundleSettings__port',
    'AbuseCounterBundleSettings__database',
    'AbuseCounterBundleSettings__clientName',
    'AbuseCounterBundleSettings__allowAdmin',
    'AbuseCounterBundleSettings__reconnectRetryPolicy',
    'AbuseCounterBundleSettings__abortOnConnectFail',
    'AbuseCounterBundleSettings__password',
    'AbuseControlSettings__Delivery__MaxEmailDeliveriesPerAccountPerHour',
    'AbuseControlSettings__Delivery__MaxSmsDeliveriesPerAccountPerHour',
    'AbuseControlSettings__Delivery__MaxEmailDeliveriesPerIpPerHour',
    'AbuseControlSettings__Delivery__MaxSmsDeliveriesPerIpPerHour',
    'AbuseControlSettings__PasswordReset__MaxRequestsPerAccountPerHour',
    'AbuseControlSettings__PasswordReset__MaxRequestsPerIdentifierPerHour',
    'AbuseControlSettings__PasswordReset__MaxRequestsPerIpPerHour',
    'PasswordResetSettings__RequestCooldownSeconds',
    'PasswordResetSettings__DailyRequestLimitPerAccount',
    'PasswordResetSettings__DailyRequestLimitPerDestination',
    'PasswordResetSettings__DailyRequestLimitPerIp',
    'HostingSettings__ConfigureKestrel',
    'HostingSettings__Port',
    'HostingSettings__BindAddress',
    'HostingSettings__UseHttps',
    'HostingSettings__Protocols',
    'HostingSettings__UseHttpsRedirection',
    'HostingSettings__UseForwardedHeaders',
    'HostingSettings__ForwardLimit',
    'HostingSettings__RequireHeaderSymmetry',
    'HostingSettings__TrustAllForwardedHeaderProxies',
    'SystemTestSettings__Enabled',
    'SystemTestSettings__EnableTestInspectionEndpoints',
    'SystemTestSettings__TestKey',
    'SystemTestSettings__DeliveryCaptureConnection',
    'TREEHAMMOCK_SYSTEM_BASE_URL',
    'TREEHAMMOCK_SYSTEM_TEST_KEY'
)

foreach ($key in $environmentKeys) {
    $previousEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}

$apiProcess = $null
try {
    $env:ASPNETCORE_ENVIRONMENT = 'ContainerReverseProxy'
    $env:DOTNET_ENVIRONMENT = 'ContainerReverseProxy'
    $env:ASPNETCORE_URLS = 'http://0.0.0.0:5001'

    $env:DatabaseSettings__servers = '127.0.0.1'
    $env:DatabaseSettings__database = 'treehammock'
    $env:DatabaseSettings__userId = 'treehammock'
    $env:DatabaseSettings__password = 'treehammock-password'
    $env:DatabaseSettings__lc_collation = 'en_US.UTF-8'

    $env:ActiveUserBundleSettings__servers = '127.0.0.1'
    $env:ActiveUserBundleSettings__port = '6379'
    $env:ActiveUserBundleSettings__database = '0'
    $env:ActiveUserBundleSettings__clientName = 'treehammock-api-host'
    $env:ActiveUserBundleSettings__allowAdmin = 'false'
    $env:ActiveUserBundleSettings__reconnectRetryPolicy = '5000'
    $env:ActiveUserBundleSettings__abortOnConnectFail = 'false'
    $env:ActiveUserBundleSettings__password = ''

    $env:TwoFactorSessionBundleSettings__servers = '127.0.0.1'
    $env:TwoFactorSessionBundleSettings__port = '6379'
    $env:TwoFactorSessionBundleSettings__database = '1'
    $env:TwoFactorSessionBundleSettings__clientName = 'treehammock-api-host-2fa'
    $env:TwoFactorSessionBundleSettings__allowAdmin = 'false'
    $env:TwoFactorSessionBundleSettings__reconnectRetryPolicy = '5000'
    $env:TwoFactorSessionBundleSettings__abortOnConnectFail = 'false'
    $env:TwoFactorSessionBundleSettings__password = ''

    $env:AbuseCounterBundleSettings__servers = '127.0.0.1'
    $env:AbuseCounterBundleSettings__port = '6379'
    $env:AbuseCounterBundleSettings__database = '2'
    $env:AbuseCounterBundleSettings__clientName = 'treehammock-api-host-abuse-counters'
    $env:AbuseCounterBundleSettings__allowAdmin = 'false'
    $env:AbuseCounterBundleSettings__reconnectRetryPolicy = '5000'
    $env:AbuseCounterBundleSettings__abortOnConnectFail = 'false'
    $env:AbuseCounterBundleSettings__password = ''

    # The host-backed system lane exercises many happy-path flows from one loopback IP.
    # Keep production abuse controls enabled, but raise shared-IP test ceilings so
    # unrelated end-to-end scenarios do not trip each other's delivery throttles.
    $env:AbuseControlSettings__Delivery__MaxEmailDeliveriesPerAccountPerHour = '100'
    $env:AbuseControlSettings__Delivery__MaxSmsDeliveriesPerAccountPerHour = '100'
    $env:AbuseControlSettings__Delivery__MaxEmailDeliveriesPerIpPerHour = '100'
    $env:AbuseControlSettings__Delivery__MaxSmsDeliveriesPerIpPerHour = '100'
    $env:AbuseControlSettings__PasswordReset__MaxRequestsPerAccountPerHour = '100'
    $env:AbuseControlSettings__PasswordReset__MaxRequestsPerIdentifierPerHour = '100'
    $env:AbuseControlSettings__PasswordReset__MaxRequestsPerIpPerHour = '100'
    $env:PasswordResetSettings__RequestCooldownSeconds = '0'
    $env:PasswordResetSettings__DailyRequestLimitPerAccount = '100'
    $env:PasswordResetSettings__DailyRequestLimitPerDestination = '100'
    $env:PasswordResetSettings__DailyRequestLimitPerIp = '100'

    $env:HostingSettings__ConfigureKestrel = 'true'
    $env:HostingSettings__Port = '5001'
    $env:HostingSettings__BindAddress = '0.0.0.0'
    $env:HostingSettings__UseHttps = 'false'
    $env:HostingSettings__Protocols = 'Http1AndHttp2'
    $env:HostingSettings__UseHttpsRedirection = 'false'
    $env:HostingSettings__UseForwardedHeaders = 'true'
    $env:HostingSettings__ForwardLimit = '1'
    $env:HostingSettings__RequireHeaderSymmetry = 'true'
    $env:HostingSettings__TrustAllForwardedHeaderProxies = 'true'
    $env:SystemTestSettings__Enabled = 'true'
    $env:SystemTestSettings__EnableTestInspectionEndpoints = 'true'
    $env:SystemTestSettings__TestKey = 'treehammock-system-test-key'
    $env:SystemTestSettings__DeliveryCaptureConnection = 'Host=127.0.0.1;Port=5432;Database=treehammock;Username=treehammock;Password=treehammock-password'
    $env:TREEHAMMOCK_SYSTEM_BASE_URL = 'http://localhost:8080'
    $env:TREEHAMMOCK_SYSTEM_TEST_KEY = 'treehammock-system-test-key'

    & dotnet restore treehammock.Tests.System/treehammock.Tests.System.csproj --locked-mode

    $apiProcess = Start-Process -FilePath 'dotnet' -ArgumentList @(
        'run',
        '--project', 'treehammock.csproj',
        '--configuration', 'Release',
        '--no-restore',
        '--urls', 'http://0.0.0.0:5001'
    ) -PassThru -RedirectStandardOutput '.artifacts/system-host-api.out.log' -RedirectStandardError '.artifacts/system-host-api.err.log'

    Wait-ForSystemReadiness

    & dotnet test treehammock.Tests.System/treehammock.Tests.System.csproj --no-restore --logger 'trx;LogFileName=treehammock-system-host-tests.trx'
    if ($LASTEXITCODE -ne 0) {
        Write-Host ''
        Write-Host 'System host API stdout (.artifacts/system-host-api.out.log):'
        if (Test-Path '.artifacts/system-host-api.out.log') { Get-Content '.artifacts/system-host-api.out.log' -Tail 200 }
        Write-Host ''
        Write-Host 'System host API stderr (.artifacts/system-host-api.err.log):'
        if (Test-Path '.artifacts/system-host-api.err.log') { Get-Content '.artifacts/system-host-api.err.log' -Tail 200 }
        exit $LASTEXITCODE
    }
}
finally {
    if ($apiProcess -ne $null -and -not $apiProcess.HasExited) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    }

    & docker compose @composeFiles down --volumes --remove-orphans

    foreach ($key in $environmentKeys) {
        [Environment]::SetEnvironmentVariable($key, $previousEnvironment[$key], 'Process')
    }
}
