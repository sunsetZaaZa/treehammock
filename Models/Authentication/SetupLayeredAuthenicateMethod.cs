using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;

using treehammock.RiggingSupport.Enum;

namespace treehammock.Models.Authentication;

public class SetupLayeredAuthenticateMethodRequest : IValidatableObject
{
    public const int MaxContactLength = 320;

        [SetsRequiredMembers]
    public SetupLayeredAuthenticateMethodRequest()
    {
        method = TwoFactorAuthMethod.NONE;
        contact = string.Empty;
        countryCode = null;
        required = true;
    }

[SetsRequiredMembers]
    public SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod method, string contact, short? countryCode, bool required)
    {
        (this.method, this.contact, this.countryCode, this.required) = (method, contact, countryCode, required);
    }

    [EnumDataType(typeof(TwoFactorAuthMethod))]
    public TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxContactLength)]
    public string contact { get; set; } = string.Empty;

    [Range(1, short.MaxValue)]
    public short? countryCode { get; set; }

    public bool required { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (method == TwoFactorAuthMethod.NONE)
        {
            yield return new ValidationResult(
                "A supported two-factor method is required.",
                new[] { nameof(method) });
        }
    }
}

public class SetupLayeredAuthenticateMethodResponse
{
    [SetsRequiredMembers]
    public SetupLayeredAuthenticateMethodResponse(bool status)
    {
        this.status = status;
    }

    public required bool status { get; set; }
}

public class VerifyLayeredAuthenticateMethodRequest : IValidatableObject
{
    public const int MinCodeLength = 1;
    public const int MaxCodeLength = 128;

        [SetsRequiredMembers]
    public VerifyLayeredAuthenticateMethodRequest()
    {
        method = TwoFactorAuthMethod.NONE;
        codeKey = string.Empty;
    }

[SetsRequiredMembers]
    public VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod method, string codeKey)
    {
        (this.method, this.codeKey) = (method, codeKey);
    }

    [EnumDataType(typeof(TwoFactorAuthMethod))]
    public TwoFactorAuthMethod method { get; set; } = TwoFactorAuthMethod.NONE;

    [Required(AllowEmptyStrings = false)]
    [StringLength(MaxCodeLength, MinimumLength = MinCodeLength)]
    public string codeKey { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (method == TwoFactorAuthMethod.NONE)
        {
            yield return new ValidationResult(
                "A supported two-factor method is required.",
                new[] { nameof(method) });
        }
    }
}
