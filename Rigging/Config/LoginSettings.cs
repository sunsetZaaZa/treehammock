using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public class LoginSettings
{
    [Range(1, 20)]
    public int PasswordRetryLimit { get; set; }

    [Range(1, 20)]
    public int TwoAuthRetryLimit { get; set; }

    [Range(0, 3600)]
    public int TwoFactorChallengeResendCooldownSeconds { get; set; } = 30;

    [Required]
    [MinLength(16)]
    public string TwoFactorChallengePepper { get; set; } = string.Empty;

    [Range(1, int.MaxValue)]
    public int Argon2Iterations { get; set; }

    [Range(1, int.MaxValue)]
    public int Argon2MemoryUsePer { get; set; }
}
