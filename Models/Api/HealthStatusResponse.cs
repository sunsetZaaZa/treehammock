using treehammock.Rigging.Health;

namespace treehammock.Models.Api;

public sealed class HealthStatusResponse
{
    public HealthStatusResponse(string status)
        : this(status, Array.Empty<HealthDependencyResult>())
    {
    }

    public HealthStatusResponse(string status, IReadOnlyList<HealthDependencyResult> dependencies)
    {
        this.status = status;
        this.dependencies = dependencies;
    }

    public string status { get; }

    public IReadOnlyList<HealthDependencyResult> dependencies { get; }

    public static HealthStatusResponse FromReport(HealthDependencyReport report)
    {
        return new HealthStatusResponse(report.Status, report.dependencies);
    }
}
