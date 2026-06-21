# Test Command Guide

This guide explains the purpose, feature set, strengths, and tradeoffs of the common validation commands used in this project.

Use this when deciding whether you need a quick local correctness check, focused integration coverage, or a production-like system-stack smoke run.

## Command summary

| Command | Main purpose | Scope | Best used for |
|---|---|---|---|
| `dotnet test` | Broad .NET test run from the current project or solution context. | Whatever test projects are discovered from the current directory, project, or solution. | General local health check before committing or before a focused test pass. |
| `dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"` | Focused integration test run for the main test project. | Tests in `treehammock.Tests` whose fully qualified name contains `treehammock.Tests.Integration`. | Auth, login, password reset, 2FA, controller, service, and in-memory integration regression PRs. |
| `.\eng\docker-host-system-stack-tests.cmd` | Host-backed Docker system-stack test lane. | PostgreSQL, Dragonfly, and HAProxy in Docker; ASP.NET backend and system tests on the host. | Final local smoke test that proves the app works through infrastructure boundaries. |

## `dotnet test`

### Purpose

`dotnet test` is the general-purpose .NET test command. Run from the repository root, it is the simplest way to ask: “Is the normal .NET test surface still healthy?”

### Feature set

- Restores and builds as needed unless `--no-restore` or `--no-build` is provided.
- Discovers tests from the current project, solution, or directory context.
- Runs unit and integration tests when they are part of the discovered test graph.
- Supports common test options such as `--configuration`, `--filter`, `--logger`, and coverage collectors.

### Pros

- Simple and easy to remember.
- Good broad regression check.
- Catches failures outside a narrow integration-test filter.
- Useful before a commit because it is less likely to miss renamed or relocated tests.

### Cons

- Less targeted than a project-specific or filter-specific test run.
- Can be slower than filtered integration or unit test commands.
- The exact scope depends on the directory and project or solution files available there.
- Does not prove Docker, PostgreSQL, Dragonfly, HAProxy, or deployment-like wiring unless those are explicitly part of the normal test graph.

### Use it when

- You want a broad local safety check.
- You have changed shared code used by both unit and integration tests.
- You want to catch test failures outside the current PR’s narrow area.

## Focused integration test command

```powershell
 dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"
```

### Purpose

This command runs the main test project but narrows execution to integration tests. It is the best fit for the auth, login, password reset, and 2FA integration PR series because those tests pin full security ceremonies rather than isolated method outputs.

### Feature set

- Targets `treehammock.Tests\treehammock.Tests.csproj` directly.
- Uses the `Debug` configuration for local development feedback.
- Filters tests to fully qualified names containing `treehammock.Tests.Integration`.
- Exercises ASP.NET Core integration hosts, controller/service flows, in-memory test fakes, and regression ceremonies covered by the integration namespace.

### Pros

- Faster and cleaner than running every test when working on integration PRs.
- Lower noise because it excludes unrelated unit tests.
- Good at catching auth/reset/2FA flow regressions.
- Works well after changes to controller actions, password reset flow, 2FA selection, method removal, and abuse-counter integration behavior.

### Cons

- Misses unit tests outside `treehammock.Tests.Integration`.
- Misses system-stack tests and real infrastructure behavior.
- Depends on namespace naming. If an integration test is moved or renamed outside `treehammock.Tests.Integration`, this filter may skip it.
- Does not replace full `dotnet test` before final validation.

### Use it when

- Working on Integration PRs.
- Iterating on password reset, login, 2FA, abuse counter, or controller integration behavior.
- You need fast feedback before running the heavier validation lanes.

## Docker host system-stack command

```powershell
.\eng\docker-host-system-stack-tests.cmd
```

### Purpose

This command runs the host-backed Docker system-stack lane. It is designed for environments where Docker can run PostgreSQL, Dragonfly, and HAProxy, while the ASP.NET backend and system tests run on the host using the local .NET SDK.

Use it to answer a different question from `dotnet test`: “Does the application still work when real infrastructure enters the room?”

### Feature set

- Starts PostgreSQL in Docker.
- Starts Dragonfly in Docker.
- Starts HAProxy in Docker.
- Runs the ASP.NET backend on the host.
- Runs `treehammock.Tests.System` on the host.
- Exercises the app through HAProxy, typically using `http://localhost:8080`.
- Covers system-level flows such as health, registration, login, 2FA setup/login, password reset paths, account delete, and lockout/unlock behavior.

### Pros

- Closest local validation lane to deployed behavior.
- Catches configuration, networking, proxy, database, and cache issues that in-memory integration tests cannot catch.
- Good final smoke test before calling a branch ready.
- Avoids needing the backend Docker image when the host can run the app directly.

### Cons

- Heavier and slower than normal `dotnet test`.
- Requires Docker and local port/environment availability.
- More moving parts means more possible local-environment failures.
- Intended as a smoke/system lane, not an exhaustive matrix. Detailed matrix coverage belongs in unit and integration tests.

### Use it when

- `dotnet test` and focused integration tests are already green.
- You are preparing a branch or PR for handoff.
- You changed infrastructure-facing code, configuration, health checks, database/cache behavior, auth flows, or system test coverage.

## Recommended local validation order

For normal development:

```powershell
dotnet test
```

For auth/reset/2FA integration PR work:

```powershell
dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"
```

Before declaring a branch ready:

```powershell
.\eng\docker-host-system-stack-tests.cmd
```

A practical full local sequence is:

```powershell
dotnet test
dotnet test .\treehammock.Tests\treehammock.Tests.csproj --configuration Debug --filter "FullyQualifiedName~treehammock.Tests.Integration"
.\eng\docker-host-system-stack-tests.cmd
```

## How to interpret failures

| Failing command | Most likely meaning | First place to look |
|---|---|---|
| `dotnet test` | General code/test regression. | Failing unit or integration test output. |
| Focused integration command | Security ceremony or integration-flow regression. | `treehammock.Tests/Integration`, controller/service changes, test fakes. |
| Docker host system-stack command | Runtime stack, infrastructure, proxy, database, cache, or environment issue. | `eng/docker-host-system-stack-tests.*`, Docker logs, HAProxy/backend logs, system test output. |

## Relationship to validation scripts

The README also documents wrapper scripts such as `eng/validate.*` and `eng/build-proof.*`. Prefer wrappers for CI-like proof runs because they standardize restore, build, and test options. Use the raw commands in this guide when you need targeted local diagnostics or fast iteration.
