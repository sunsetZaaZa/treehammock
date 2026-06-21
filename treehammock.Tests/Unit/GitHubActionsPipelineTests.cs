using Shouldly;

namespace treehammock.Tests.Unit;

public class GitHubActionsPipelineTests
{
    [Fact]
    public void Github_ci_runs_fast_validation_by_default_and_exposes_manual_heavy_lanes()
    {
        string ci = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-ci.yml"));

        ci.ShouldContain("name: Treehammock CI");
        ci.ShouldContain("pull_request:");
        ci.ShouldContain("push:");
        ci.ShouldContain("workflow_dispatch:");
        ci.ShouldContain("permissions:");
        ci.ShouldContain("contents: read");
        ci.ShouldContain("dotnet-unit-tests:");
        ci.ShouldContain("dotnet-integration-tests:");
        ci.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        ci.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        ci.ShouldContain("actions/checkout@v6");
        ci.ShouldContain("actions/setup-dotnet@v5");
        ci.ShouldContain("actions/upload-artifact@v7");
        ci.ShouldContain("dotnet-version: 8.0.x");
        ci.ShouldContain("cache-dependency-path:");

        ci.ShouldContain("dotnet-sql-contracts:");
        ci.ShouldContain("docker-direct-integration:");
        ci.ShouldContain("docker-proxy-integration:");
        ci.ShouldContain("docker-system-stack:");
        ci.ShouldContain("github.event.inputs.lane == 'sql'");
        ci.ShouldContain("github.event.inputs.lane == 'docker-direct'");
        ci.ShouldContain("github.event.inputs.lane == 'docker-proxy'");
        ci.ShouldContain("github.event.inputs.lane == 'docker-system'");
        ci.ShouldContain("github.event_name == 'workflow_dispatch'");
        ci.ShouldContain("postgres:16");
        ci.ShouldContain("TREEHAMMOCK_RUN_DEFERRED_SQL_CONTRACTS: \"true\"");
        ci.ShouldContain("./eng/docker-host-system-stack-tests.sh");
        ci.ShouldContain("docker-compose.local-system.yml");
    }

    [Fact]
    public void Github_release_workflow_defaults_to_1_0_0_and_runs_all_release_gates_before_packaging()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));

        release.ShouldContain("name: Treehammock Release");
        release.ShouldContain("group: treehammock-release-${{ github.workflow }}-${{ github.ref }}-${{ github.ref_name }}");
        release.ShouldContain("push:");
        release.ShouldContain("branches:");
        release.ShouldContain("- main");
        release.ShouldContain("default: v1.0.0");
        release.ShouldNotContain("tags:");
        release.ShouldNotContain("v*.*.*");
        release.ShouldContain("permissions:");
        release.ShouldContain("contents: write");
        release.ShouldContain("packages: write");

        release.ShouldContain("release-preflight:");
        release.ShouldContain("release_mode=\"bootstrap\"");
        release.ShouldContain("release_tag=\"v1.0.0\"");
        release.ShouldContain("ref: main");
        release.ShouldContain("git fetch --no-tags --prune origin +refs/heads/main:refs/remotes/origin/main");
        release.ShouldContain("main_ref=\"refs/remotes/origin/main\"");
        release.ShouldContain("initial_main_commit=\"$(git rev-list --first-parent --max-parents=0 \"${main_ref}\" | tail -n 1)\"");
        release.ShouldContain("current_main_commit=\"$(git rev-parse \"${main_ref}\")\"");
        release.ShouldContain("trigger_commit=\"${GITHUB_SHA}\"");
        release.ShouldContain("checkout_ref=\"${initial_main_commit}\"");
        release.ShouldContain("Release workflow is pinned to v1.0.0 only.");
        release.ShouldContain("Release v1.0.0 only runs from the initial commit to main (${initial_main_commit}); trigger commit was ${trigger_commit}.");
        release.ShouldContain("Manual v1.0.0 release must target the initial commit to main (${initial_main_commit}); requested target resolved to ${requested_ref}.");
        release.ShouldContain("gh release view \"${release_tag}\"");
        release.ShouldContain("gh api \"repos/${GITHUB_REPOSITORY}/git/ref/tags/${release_tag}\"");
        release.ShouldContain("should_release=\"false\"");
        release.ShouldContain("if: ${{ needs.release-preflight.outputs.should_release == 'true' }}");
        release.ShouldContain("gh release upload \"$RELEASE_TAG\" artifacts/* --clobber --repo \"$GH_REPO\"");
        release.ShouldContain("release-dotnet-unit-gate:");
        release.ShouldContain("release-dotnet-integration-gate:");
        release.ShouldContain("release-dotnet-sql-gate:");
        release.ShouldContain("release-docker-direct-gate:");
        release.ShouldContain("release-docker-proxy-gate:");
        release.ShouldContain("release-docker-system-gate:");
        release.ShouldContain("release-package-api:");
        release.ShouldContain("create-github-release:");

        release.ShouldContain("./eng/dotnet-unit-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/dotnet-integration-tests.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/sql-contracts.sh --configuration \"$BUILD_CONFIGURATION\" --locked-restore");
        release.ShouldContain("./eng/docker-http-contracts-direct.sh");
        release.ShouldContain("./eng/docker-http-contracts-proxy.sh");
        release.ShouldContain("./eng/docker-host-system-stack-tests.sh");
        release.ShouldContain("docker-compose.local-system.yml");

        release.ShouldContain("release-dotnet-unit-gate");
        release.ShouldContain("release-dotnet-integration-gate");
        release.ShouldContain("release-dotnet-sql-gate");
        release.ShouldContain("release-docker-direct-gate");
        release.ShouldContain("release-docker-proxy-gate");
        release.ShouldContain("release-docker-system-gate");
    }

    [Fact]
    public void Github_release_workflow_publishes_versioned_assets_and_can_create_the_github_release()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));

        release.ShouldContain("RELEASE_PACKAGE_NAME: treehammock-api");
        release.ShouldContain("release_archive=\"${RELEASE_PACKAGE_NAME}-${release_tag}.tar.gz\"");
        release.ShouldContain("release_checksum=\"${RELEASE_PACKAGE_NAME}-${release_tag}.sha256\"");
        release.ShouldContain("dotnet publish treehammock.csproj");
        release.ShouldContain("-p:Version=\"$RELEASE_VERSION\"");
        release.ShouldContain("-p:PackageVersion=\"$RELEASE_VERSION\"");
        release.ShouldContain("-p:AssemblyVersion=\"$RELEASE_ASSEMBLY_VERSION\"");
        release.ShouldContain("-p:FileVersion=\"$RELEASE_ASSEMBLY_VERSION\"");
        release.ShouldContain("-p:InformationalVersion=\"$RELEASE_TAG\"");
        release.ShouldContain("cp LICENSE artifacts/publish/treehammock-api/LICENSE");
        release.ShouldContain("tar -C artifacts/publish -czf \"artifacts/${RELEASE_ARCHIVE}\" treehammock-api");
        release.ShouldContain("sha256sum \"${RELEASE_ARCHIVE}\"");
        release.ShouldContain("actions/download-artifact@v7");
        release.ShouldContain("GH_REPO: ${{ github.repository }}");
        release.ShouldContain("gh release view \"$RELEASE_TAG\" --repo \"$GH_REPO\"");
        release.ShouldContain("release_args=(release create \"$RELEASE_TAG\" artifacts/* --title \"Tree Hammock ${RELEASE_TAG}\" --generate-notes --repo \"$GH_REPO\")");
        release.ShouldContain("gh \"${release_args[@]}\"");
        release.ShouldContain("gh release upload \"$RELEASE_TAG\" artifacts/* --clobber --repo \"$GH_REPO\"");
        release.ShouldContain("--title \"Tree Hammock ${RELEASE_TAG}\"");
        release.ShouldContain("--generate-notes");
        release.ShouldContain("RELEASE_MODE: ${{ needs.release-preflight.outputs.release_mode }}");
        release.ShouldContain("if [ \"$RELEASE_MODE\" != \"tag\" ]; then");
        release.ShouldNotContain("release_mode=\"tag\"");
        release.ShouldContain("--target \"$CHECKOUT_REF\"");
    }

    [Fact]
    public void Github_release_workflow_is_pinned_to_v1_0_0_initial_main_commit_only()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));

        release.ShouldContain("push:");
        release.ShouldContain("branches:");
        release.ShouldContain("- main");
        release.ShouldContain("release_mode=\"bootstrap\"");
        release.ShouldContain("release_tag=\"v1.0.0\"");
        release.ShouldContain("ref: main");
        release.ShouldContain("git fetch --no-tags --prune origin +refs/heads/main:refs/remotes/origin/main");
        release.ShouldContain("main_ref=\"refs/remotes/origin/main\"");
        release.ShouldContain("initial_main_commit=\"$(git rev-list --first-parent --max-parents=0 \"${main_ref}\" | tail -n 1)\"");
        release.ShouldContain("current_main_commit=\"$(git rev-parse \"${main_ref}\")\"");
        release.ShouldContain("trigger_commit=\"${GITHUB_SHA}\"");
        release.ShouldContain("checkout_ref=\"${initial_main_commit}\"");
        release.ShouldContain("Release workflow is pinned to v1.0.0 only.");
        release.ShouldContain("Release v1.0.0 only runs from the initial commit to main (${initial_main_commit}); trigger commit was ${trigger_commit}.");
        release.ShouldContain("Manual v1.0.0 release must target the initial commit to main (${initial_main_commit}); requested target resolved to ${requested_ref}.");
        release.ShouldContain("GitHub Release ${release_tag} already exists.");
        release.ShouldContain("Git tag ${release_tag} already exists.");
        release.ShouldContain("should_release=\"false\"");
        release.ShouldContain("Skipping ${release_tag}: ${skip_reason}");
        release.ShouldNotContain("Temporary debug posture: run the full release gate/package lane for every");
        release.ShouldContain("if: ${{ needs.release-preflight.outputs.should_release == 'true' }}");
        release.ShouldContain("if [ \"$RELEASE_MODE\" != \"tag\" ]; then");
        release.ShouldContain("release_args+=(--target \"$CHECKOUT_REF\")");
        release.ShouldContain("gh release upload \"$RELEASE_TAG\" artifacts/* --clobber --repo \"$GH_REPO\"");
    }

    [Fact]
    public void Github_release_workflow_can_publish_opt_in_ghcr_image()
    {
        string release = File.ReadAllText(ProjectFile(".github", "workflows", "treehammock-release.yml"));
        string script = File.ReadAllText(ProjectFile("eng", "release-container-publish.sh"));

        release.ShouldContain("release-ghcr-image:");
        release.ShouldContain("publish_ghcr");
        release.ShouldContain("vars.PUBLISH_GHCR == 'true'");
        release.ShouldContain("REGISTRY_KIND: github");
        release.ShouldContain("GITHUB_CONTAINER_REGISTRY=\"ghcr.io\"");
        release.ShouldContain("GITHUB_CONTAINER_IMAGE=\"ghcr.io/${repository_lower}\"");
        release.ShouldContain("name: treehammock-ghcr-image");
        release.ShouldContain("./eng/release-container-publish.sh");

        script.ShouldContain("REGISTRY_KIND              gitlab | generic | dockerhub | aws-ecr | github");
        script.ShouldContain("GitHub Container Registry:");
        script.ShouldContain("login_github()");
        script.ShouldContain("GITHUB_CONTAINER_REGISTRY=\"${GITHUB_CONTAINER_REGISTRY:-ghcr.io}\"");
        script.ShouldContain("require_var GITHUB_CONTAINER_IMAGE");
        script.ShouldContain("require_var GITHUB_TOKEN");
        script.ShouldContain("github|ghcr)");
    }

    [Fact]
    public void Release_version_is_pinned_to_1_0_0_for_msbuild_and_ci()
    {
        string props = File.ReadAllText(ProjectFile("Directory.Build.props"));

        props.ShouldContain("<Product>Raptor Balcony</Product>");
        props.ShouldContain("<VersionPrefix>1.0.0</VersionPrefix>");
        props.ShouldContain("<PackageVersion>1.0.0</PackageVersion>");
        props.ShouldContain("<AssemblyVersion>1.0.0.0</AssemblyVersion>");
        props.ShouldContain("<FileVersion>1.0.0.0</FileVersion>");
        props.ShouldContain("<InformationalVersion>1.0.0</InformationalVersion>");
        props.ShouldContain("'$(GITHUB_ACTIONS)' == 'true'");
        props.ShouldContain("'$(GITLAB_CI)' == 'true'");
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }
}
