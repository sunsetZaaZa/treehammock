using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class SensitiveActionSettings
{
    [Range(16, 128)]
    public int TokenBytes { get; set; } = 32;

    [Range(1, 60)]
    public int ExpirationMinutes { get; set; } = 10;

    public bool ConsumeExistingTokensOnIssue { get; set; } = true;
}
