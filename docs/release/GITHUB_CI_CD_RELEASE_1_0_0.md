# GitHub CI/CD release lane for 1.0.0

This document defines the GitHub Actions release lane that mirrors the existing GitLab child-pipeline design without changing the release contract. GitHub Actions is an additional CI/CD surface for Treehammock / Raptor Balcony 1.0.0, not a replacement for the existing GitLab workflows.

## Goals

- Keep normal pull-request and branch validation fast by running only .NET unit and in-process integration tests by default.
- Keep PostgreSQL SQL contracts and Docker Compose system tests explicit heavy lanes.
- Run every release gate before packaging or publishing `v1.0.0`.
- Restrict the GitHub release lane to the initial commit to the `main` branch of a fresh repository for the one-time `v1.0.0` bootstrap release.
- Produce a versioned API publish archive and SHA256 checksum for the GitHub release.
- Allow optional GitHub Container Registry publishing without requiring it for source release creation.

## Workflow files

| Workflow | File | Trigger | Purpose |
| --- | --- | --- | --- |
| Treehammock CI | `.github/workflows/treehammock-ci.yml` | `pull_request`, selected branch `push`, and manual `workflow_dispatch` | Runs the fast validation lanes by default. Manual dispatch can run SQL contracts and Docker lanes. |
| Treehammock Release | `.github/workflows/treehammock-release.yml` | first `main` push or manual `workflow_dispatch` | Bootstraps `v1.0.0` only when the resolved target is the initial commit to `main` and no `v1.0.0` tag or Release exists; later automatic runs skip release work. |

## Normal CI behavior

Pull requests and branch pushes run:

1. `./eng/check-locks.sh`
2. `./eng/dotnet-unit-tests.sh --configuration "$BUILD_CONFIGURATION" --locked-restore`
3. `./eng/dotnet-integration-tests.sh --configuration "$BUILD_CONFIGURATION" --locked-restore`

The CI workflow uploads TRX files as artifacts even when a lane fails. Manual dispatch exposes these lanes:

- `all`
- `unit`
- `integration`
- `sql`
- `docker-direct`
- `docker-proxy`
- `docker-system`

The `sql` lane starts disposable PostgreSQL 16 and sets:

```text
TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS=true
TREEHAMMOCK_DB_CONTRACT_CONNECTION=Host=localhost;Port=5432;Database=treehammock_contract;Username=postgres;Password=postgres
```

GitHub Actions emits and documents `TREEHAMMOCK_*` as the SQL and release contract. No legacy product-prefix aliases are supported after PR 9. See `TREEHAMMOCK_ENVIRONMENT_VARIABLES.md` for the current variable list.

The Docker lanes call the existing repository scripts:

- `./eng/docker-http-contracts-direct.sh`
- `./eng/docker-http-contracts-proxy.sh`
- `./eng/docker-host-system-stack-tests.sh`

The CI/release system lane is host-backed: PostgreSQL, Dragonfly, and HAProxy run in Docker, while the API and system tests run on the GitHub-hosted .NET SDK. This avoids making the system lane depend on pulling `mcr.microsoft.com/dotnet/sdk:8.0` as a Compose service image, which has proven flaky on some GitHub runner network paths.

Each Docker lane tears down the Compose stack in an `always()` cleanup step.

## Release behavior

The release workflow defaults manual dispatch to `v1.0.0`. It also runs automatically on pushes to `main`. It intentionally does not listen to tag pushes, so the automatic 1.0.0 bootstrap path is the only automatic GitHub Release path.

For a `main` branch push, the workflow enters bootstrap mode: it targets `v1.0.0`, resolves the pushed commit SHA, and computes the initial commit on the first-parent history of `origin/main`. The release is allowed only when the trigger commit equals that initial main commit. It also checks GitHub for an existing `v1.0.0` Release or tag. If the trigger is not the initial main commit, or if the tag or Release already exists, every downstream release gate/package/publish job is skipped. This makes the fresh repository initial `main` commit the only automatic source for the 1.0.0 release.

Release gates run in this order before packaging when the preflight says a release should run:

1. Release metadata preflight validates the `vMAJOR.MINOR.PATCH` tag format and computes package names.
2. Release .NET unit gate.
3. Release .NET in-process integration gate.
4. Release PostgreSQL SQL gate against disposable PostgreSQL 16.
5. Release Docker direct HTTP integration gate.
6. Release Docker HAProxy HTTP integration gate.
7. Release Docker host-backed system stack gate.
8. Release package job.
9. Optional GitHub Container Registry image job.
10. GitHub Release creation.

## Release artifacts

For `v1.0.0`, the package job creates:

- `treehammock-api-v1.0.0.tar.gz`
- `treehammock-api-v1.0.0.sha256`

The package job passes release version properties into `dotnet publish`:

- `Version=1.0.0`
- `PackageVersion=1.0.0`
- `AssemblyVersion=1.0.0.0`
- `FileVersion=1.0.0.0`
- `InformationalVersion=v1.0.0`

The repository also pins default MSBuild release metadata in `Directory.Build.props` so local builds and CI builds share the same 1.0.0 identity unless an explicit release workflow override is supplied.

## Optional GHCR publishing

GitHub Container Registry publishing is intentionally opt-in:

- Manual dispatch: set `publish_ghcr=true`.
- Initial-main-commit push: set repository variable `PUBLISH_GHCR=true`.

When enabled, `eng/release-container-publish.sh` uses `REGISTRY_KIND=github` and publishes the Docker `api` target to:

```text
ghcr.io/<owner>/<repo>
```

Stable tags such as `v1.0.0` also receive `latest` when `PUSH_LATEST_FOR_STABLE=true`. Prerelease tags such as `v1.0.0-rc.1` do not receive `latest`.

## Operator path for 1.0.0

Preferred bootstrap release for the first GitHub commit:

```bash
git push origin main
```

On that initial-main-commit push, the workflow creates `v1.0.0` after all gates pass. Later `main` pushes resolve to a non-initial commit, or see the existing `v1.0.0` tag or Release, and skip release work.

Manual release from GitHub Actions for explicit recovery:

1. Open **Actions**.
2. Select **Treehammock Release**.
3. Choose **Run workflow**.
4. Use `release_tag=v1.0.0` and `target_ref=<initial-main-commit-sha>`.
5. Leave `create_release=true`.
6. Enable `publish_ghcr` only when the container image should be published to GHCR.

The manual path creates the release from `target_ref` after all release gates pass only when the resolved target is the initial commit to `main`. Existing GitHub Releases or tags cause preflight to skip downstream release work so the once-only release contract stays intact.

## License metadata

The release package includes the repository `LICENSE` file and project metadata declares `PackageLicenseExpression` as `MIT`.
