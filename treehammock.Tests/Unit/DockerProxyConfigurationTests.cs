using Shouldly;

namespace treehammock.Tests.Unit;

public class DockerProxyConfigurationTests
{
    [Fact]
    public void Compose_stack_defines_optional_haproxy_proxy_service()
    {
        string compose = File.ReadAllText(Path.Combine(ProjectRoot(), "docker-compose.integration.yml"));

        compose.ShouldContain("  haproxy:");
        compose.ShouldContain("profiles: [\"proxy\"]");
        compose.ShouldContain("8080:8080");
        compose.ShouldContain("./deploy/haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro");
        compose.ShouldContain("api:");
        compose.ShouldContain("condition: service_started");
    }

    [Fact]
    public void Proxy_override_enables_container_reverse_proxy_profile_for_api()
    {
        string overrideFile = File.ReadAllText(Path.Combine(ProjectRoot(), "docker-compose.api-proxy.yml"));

        overrideFile.ShouldContain("ASPNETCORE_ENVIRONMENT: ContainerReverseProxy");
        overrideFile.ShouldContain("DOTNET_ENVIRONMENT: ContainerReverseProxy");
        overrideFile.ShouldContain("HostingSettings__UseForwardedHeaders: \"true\"");
        overrideFile.ShouldContain("HostingSettings__TrustAllForwardedHeaderProxies: \"true\"");
    }

    [Fact]
    public void Haproxy_routes_to_api_service_and_health_checks_ready_endpoint()
    {
        string config = File.ReadAllText(Path.Combine(ProjectRoot(), "deploy", "haproxy", "haproxy.cfg"));

        config.ShouldContain("bind *:8080");
        config.ShouldContain("option forwardfor");
        config.ShouldContain("http-request set-header X-Forwarded-Proto http");
        config.ShouldContain("http-request set-header X-Forwarded-Host %[req.hdr(Host)]");
        config.ShouldContain("balance roundrobin");
        config.ShouldContain("option httpchk GET /health/ready");
        config.ShouldContain("http-check expect status 200");
        config.ShouldContain("server-template api 8 api:5001 check resolvers docker init-addr libc,none");
        config.ShouldContain("Cloudflare in front of HAProxy");
        config.ShouldContain("forbid origin bypass");
        config.ShouldContain("CF-Connecting-IP");
        config.ShouldContain("True-Client-IP");
        config.ShouldContain("X-Cloudflare-Ray");
        config.ShouldContain("http-request deny unless from_cloudflare");
        config.ShouldContain("Production behind Cloudflare should set this to https");
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
}
