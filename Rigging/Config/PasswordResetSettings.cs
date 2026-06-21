using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class PasswordResetSettings
{
    public const int MinimumCodeLength = 6;
    public const int MaximumCodeLength = 16;

    [Range(MinimumCodeLength, MaximumCodeLength)]
    public int CodeLength { get; set; } = 8;

    [Required]
    [MinLength(16)]
    public string CodeHashPepper { get; set; } = string.Empty;

    [Range(2, 60)]
    public int ExpirationMinutes { get; set; } = 2;

    [Range(1, 10)]
    public int MaxAttempts { get; set; } = 5;

    [Range(0, 3600)]
    public int RequestCooldownSeconds { get; set; } = 60;

    [Range(1, int.MaxValue)]
    public int DailyRequestLimitPerAccount { get; set; } = 5;

    [Range(1, int.MaxValue)]
    public int DailyRequestLimitPerDestination { get; set; } = 5;

    [Range(1, int.MaxValue)]
    public int DailyRequestLimitPerIp { get; set; } = 20;

    [Range(1, 168)]
    public int DailyRequestWindowHours { get; set; } = 24;

    [Range(1, 1440)]
    public int RateLimitBlockMinutes { get; set; } = 30;

    public bool CaptchaChallengeEnabled { get; set; } = false;

    [Range(1, 100)]
    public int CaptchaChallengeAfterRequests { get; set; } = 3;
}
