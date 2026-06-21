using System.ComponentModel.DataAnnotations;

namespace treehammock.Rigging.Config;

public sealed class TotpSettings : IValidatableObject
{
    public const int MinimumSecretBytes = 20;
    public const int MaximumSecretBytes = 64;
    public const int MinimumPeriodSeconds = 15;
    public const int MaximumPeriodSeconds = 120;
    public const int RequiredProtectionKeyBytes = 32;
    public const int MinimumSetupIdBytes = 16;
    public const int MaximumSetupIdBytes = 64;


    [Required]
    public string Issuer { get; set; } = "Treehammock";

    [Range(6, 8)]
    public int Digits { get; set; } = 6;

    [Range(MinimumPeriodSeconds, MaximumPeriodSeconds)]
    public int PeriodSeconds { get; set; } = 30;

    [Range(0, 2)]
    public int AllowedClockSkewSteps { get; set; } = 1;

    [Required]
    public string HashAlgorithm { get; set; } = "SHA1";

    [Range(MinimumSecretBytes, MaximumSecretBytes)]
    public int SecretBytes { get; set; } = MinimumSecretBytes;

    [Required]
    public string SecretProtectionKey { get; set; } = string.Empty;

    [Range(MinimumSetupIdBytes, MaximumSetupIdBytes)]
    public int SetupIdBytes { get; set; } = 32;

    [Range(1, 60)]
    public int SetupExpirationMinutes { get; set; } = 10;

    [Range(1, 10)]
    public short SetupMaxAttempts { get; set; } = 5;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            yield return new ValidationResult("TotpSettings Issuer is required.", [nameof(Issuer)]);
        }

        if (Digits is not (6 or 7 or 8))
        {
            yield return new ValidationResult("TotpSettings Digits must be 6, 7, or 8.", [nameof(Digits)]);
        }

        if (!IsSupportedHashAlgorithm(HashAlgorithm))
        {
            yield return new ValidationResult("TotpSettings HashAlgorithm must be SHA1, SHA256, or SHA512.", [nameof(HashAlgorithm)]);
        }

        if (!TryDecodeProtectionKey(SecretProtectionKey, out byte[] keyBytes))
        {
            yield return new ValidationResult($"TotpSettings SecretProtectionKey must be a base64-encoded {RequiredProtectionKeyBytes}-byte key.", [nameof(SecretProtectionKey)]);
        }
        else
        {
            Array.Clear(keyBytes);
        }
    }

    public static bool IsSupportedHashAlgorithm(string? algorithm)
    {
        return string.Equals(algorithm, "SHA1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(algorithm, "SHA256", StringComparison.OrdinalIgnoreCase)
            || string.Equals(algorithm, "SHA512", StringComparison.OrdinalIgnoreCase);
    }

    public static bool TryDecodeProtectionKey(string? encodedKey, out byte[] keyBytes)
    {
        keyBytes = [];
        if (string.IsNullOrWhiteSpace(encodedKey))
        {
            return false;
        }

        try
        {
            keyBytes = Convert.FromBase64String(encodedKey);
            return keyBytes.Length == RequiredProtectionKeyBytes;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
