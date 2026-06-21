# Treehammock

Treehammock is an ASP.NET Core 8 account-security API. It provides account registration, verification, login, single-session JWT authentication, two-factor authentication, password reset, account unlock, activation flows, abuse controls, and deployment health checks.

The runtime is designed around PostgreSQL for durable state and DragonflyDB/Redis-compatible cache lanes for active sessions, pending two-factor sessions, abuse counters, and idempotency guards.

## Current 1.0.0 surface

Treehammock supports:

| Area | Supported behavior |
|---|---|
| Accounts | Create account, verify account, view profile, adjust username, verify email changes, request/finalize account deletion. |
| Authentication | Password login, signed compact JWT access tokens, one active session per account, logout, logout-all, session listing, session revocation. |
| Two-factor authentication | Email, SMS key-code, and local RFC 6238 authenticator-app TOTP. Authenticator apps include clients such as Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden, Aegis, and FreeOTP. |
| Password reset | Non-enumerating email/SMS reset request, reset key-code verification, optional reset-session 2FA proof, and final password promotion. |
| Account unlock | Password-attempt lockout recovery through email or verified SMS. |
| Activation | Authenticated place, verify, and disable flows. |
| Abuse controls | Login, delivery, two-factor, password-reset, account-unlock, account-delete, public-token, activation, and authenticated mutation idempotency counters. |
| Health checks | Liveness, readiness, and dependency checks for deployment probes. |

Treehammock intentionally does not support multi-session accounts, OAuth/OIDC push challenges, encrypted JWTs, or client-selected email destinations for email two-factor. The detailed release boundary lives in `docs/release/RELEASE_FEATURE_MATRIX_1_0_0.md`.

## Repository layout

| Path | Purpose |
|---|---|
| `Controllers/` | Public HTTP API controllers. |
| `Services/` | Business logic for account, login, delivery, reset, 2FA, activation, and abuse-control flows. |
| `Repos/` | PostgreSQL-facing repository layer. |
| `Entities/` | Domain/database entities. |
| `Rigging/` | Infrastructure plumbing: authorization, cache, configuration, database baseline, health, hosting, providers, and helpers. |
| `email_templates/` | HTML and text email templates. |
| `sms_templates/` | SMS message templates. |
| `tests/http/bruno/` | Bruno HTTP contract checks for Docker lanes. |
| `treehammock.Tests/` | Unit and in-process integration tests. |
| `treehammock.Tests.SqlContracts/` | PostgreSQL SQL contract tests. |
| `treehammock.Tests.System/` | System-stack tests. |
| `eng/` | Cross-platform build, validation, Docker, SQL, and release helper scripts. |
| `docs/` | API, release, SQL, and testing reference documents. |

## Requirements

- .NET SDK 8. The repository pins SDK `8.0.100` with `rollForward: latestFeature` in `global.json`.
- Docker with Compose support for PostgreSQL, DragonflyDB, HAProxy, and full-stack validation lanes.
- Bash, PowerShell, or both. Every main `eng/*.sh` script has a PowerShell equivalent.

## Quick start

From the repository root:

```bash
./eng/restore-locks.sh
./eng/validate.sh --configuration Debug
```

Windows PowerShell:

```powershell
./eng/restore-locks.ps1
./eng/validate.ps1 -Configuration Debug
```

If PowerShell blocks local scripts because the checkout is not signed, use a process-local bypass instead of changing the machine policy:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\validate.ps1 -Configuration Debug
```

## Run the API with Docker

Run PostgreSQL, DragonflyDB, and the API directly on `http://localhost:5001`:

```bash
./eng/docker-api-direct-up.sh
```

Run the API behind HAProxy on `http://localhost:8080`:

```bash
./eng/docker-api-proxy-up.sh
```

Stop services:

```bash
./eng/docker-down.sh
```

Remove containers and named volumes:

```bash
./eng/docker-down.sh --volumes
```

The Docker stack initializes PostgreSQL from `Rigging/Database/Baseline/000_treehammock_canonical_database.sql` and wires the API to DragonflyDB using container-local environment variables.

## Useful health checks

Direct API stack:

```bash
curl http://localhost:5001/health/live
curl http://localhost:5001/health/ready
curl http://localhost:5001/health/dependencies
```

HAProxy stack:

```bash
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
curl http://localhost:8080/health/dependencies
```

`/health/live` confirms process liveness. `/health/ready` and `/health/dependencies` check required backing services before reporting ready.

## Test and validation commands

| Command | Purpose |
|---|---|
| `./eng/validate.sh --configuration Release --locked-restore` | Restore, build, unit tests, and in-process integration tests. |
| `./eng/dotnet-unit-tests.sh --configuration Release --locked-restore` | Unit-test lane only. |
| `./eng/dotnet-integration-tests.sh --configuration Release --locked-restore` | In-process integration lane only. |
| `./eng/sql-contracts.sh --configuration Release --locked-restore` | PostgreSQL SQL contract suite. Requires explicit SQL environment variables. |
| `./eng/docker-sql-contracts.sh` | SQL contract suite against Compose PostgreSQL. |
| `./eng/docker-http-contracts-direct.sh` | Bruno HTTP checks against the direct API container. |
| `./eng/docker-http-contracts-proxy.sh` | Bruno HTTP checks through HAProxy. |
| `./eng/docker-system-stack-tests.sh` | Full Compose system-stack lane. |
| `./eng/docker-host-system-stack-tests.sh` | Host-backed system-stack lane through HAProxy. |
| `./eng/docker-all-tests.sh` | Docker unit, SQL, HTTP direct, HTTP proxy, and system lanes. |
| `./eng/release-proof.sh --configuration Release` | Local release gate. Runs locked restore and dedicated release checks. |

PowerShell equivalents use the same names with `.ps1`.

For a fuller command guide, see `docs/testing/TEST_COMMAND_GUIDE.md`.

## SQL contract tests

The SQL contract suite is opt-in outside the release gate. Use a disposable PostgreSQL database and set both required variables:

```bash
export TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS=true
export TREEHAMMOCK_DB_CONTRACT_CONNECTION="Host=localhost;Database=treehammock_contract;Username=postgres;Password=postgres"
./eng/sql-contracts.sh --configuration Release --locked-restore
```

Windows PowerShell:

```powershell
$env:TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS = "true"
$env:TREEHAMMOCK_DB_CONTRACT_CONNECTION = "Host=localhost;Database=treehammock_contract;Username=postgres;Password=postgres"
./eng/sql-contracts.ps1 -Configuration Release -LockedRestore
```

## API surface

Primary public routes are grouped under these prefixes:

| Prefix | Purpose |
|---|---|
| `/account` | Registration, verification, login, profile, sessions, deletion, reauthentication, and two-factor flows. |
| `/account/unlock` | Account lockout recovery. |
| `/account/password-reset` | Password reset request, token verification, reset 2FA, and finalization. |
| `/activations` | Authenticated activation place, verify, and disable flows. |
| `/health` | Public health probes. |

The full endpoint table is maintained in `docs/release/API_ENDPOINT_MATRIX_1_0_0.md`.

## Configuration

Common configuration files:

| File | Use |
|---|---|
| `appsettings.json` | Base local settings and safe defaults. |
| `appsettings.Example.json` | Example configuration with all major setting sections visible. |
| `appsettings.Testing.json` | In-process test host profile. |
| `appsettings.LocalHttps.json` | Direct local HTTPS profile. |
| `appsettings.Container.json` | Container profile for the direct API stack. |
| `appsettings.ReverseProxy.json` | Reverse-proxy profile for HAProxy, nginx, Kubernetes ingress, or similar TLS termination. |

Important configuration sections include:

- `DatabaseSettings`
- `ActiveUserBundleSettings`
- `TwoFactorSessionBundleSettings`
- `AbuseCounterBundleSettings`
- `JWTSettings`
- `LoginSettings`
- `RegistrationSettings`
- `PasswordResetSettings`
- `SensitiveActionSettings`
- `SMTPSettings`
- `SidewalkSettings`
- `TotpSettings`
- `HostingSettings`

Use environment-variable overrides for secrets and deployment-specific values. Keep real passwords, token peppers, SMTP credentials, SMS provider credentials, and TOTP protection keys out of committed files.

## Hosting model

Treehammock can run as:

| Mode | Local endpoint | Notes |
|---|---:|---|
| Direct container API | `http://localhost:5001` | Kestrel serves the API without a reverse proxy. |
| HAProxy container edge | `http://localhost:8080` | HAProxy forwards traffic to the API container. |
| Direct local HTTPS | `https://localhost:5001` | Use `appsettings.LocalHttps.json` or equivalent environment overlay. |
| Reverse-proxy deployment | deployment-specific | Use `appsettings.ReverseProxy.json` and configure trusted forwarded headers. |

`Program.cs` reads `HostingSettings`; public ports, TLS behavior, and forwarded-header trust should be controlled through configuration instead of hardcoded changes.

## CI/CD

The repository includes both GitHub Actions and GitLab CI definitions:

| Path | Purpose |
|---|---|
| `.github/workflows/treehammock-ci.yml` | GitHub branch and pull-request validation. |
| `.github/workflows/treehammock-release.yml` | GitHub release packaging flow. |
| `.gitlab-ci.yml` | GitLab dispatcher. |
| `.gitlab/ci/pipelines/` | GitLab child pipelines for unit, integration, SQL, Docker, and release lanes. |

Release artifacts are source/API packages plus checksums. Optional container publishing is controlled by CI variables.

## Reference documents

| Document | Purpose |
|---|---|
| `docs/release/RELEASE_FEATURE_MATRIX_1_0_0.md` | Supported, limited, future, and unsupported release features. |
| `docs/release/API_ENDPOINT_MATRIX_1_0_0.md` | Public endpoint matrix. |
| `docs/release/PASSWORD_RESET_1_0_0.md` | Password-reset flow contract. |
| `docs/release/GITHUB_CI_CD_RELEASE_1_0_0.md` | GitHub CI/CD release behavior. |
| `docs/sql/SQL_CONTRACT_MATRIX_1_0_0.md` | PostgreSQL function and repository contract matrix. |
| `docs/testing/TEST_COMMAND_GUIDE.md` | Local validation and system-test command guide. |

The README is intentionally the front door. Long-form contracts stay in `docs/`, where the tiny goblin scrolls belong.

## License

Treehammock is licensed under the MIT License. See `LICENSE` for the full license text.
