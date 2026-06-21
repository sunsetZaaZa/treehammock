using treehammock.Services.SystemTesting;

namespace treehammock.Services;

public interface ISystemTestPurposeAwareSmsSender
{
    Task<bool> SendCode(string phoneNumber, string codeKey, string purpose);
}

public sealed class SystemTestSmsSender : ISmsSender, ISystemTestPurposeAwareSmsSender
{
    private readonly ISystemTestDeliveryCapture _capture;

    public SystemTestSmsSender(ISystemTestDeliveryCapture capture)
    {
        _capture = capture;
    }

    public async Task<bool> SendCode(string phoneNumber, string codeKey)
    {
        return await SendCode(phoneNumber, codeKey, "sms_code");
    }

    public async Task<bool> SendCode(string phoneNumber, string codeKey, string purpose)
    {
        string? destination = NormalizeTestPhoneNumber(phoneNumber);
        if (destination is null)
        {
            return false;
        }

        await _capture.CaptureSms(purpose, destination, $"Your Treehammock security code is {codeKey}.", codeKey);
        return true;
    }

    public async Task<bool> SendMessage(string phoneNumber, string messageBody)
    {
        string? destination = NormalizeTestPhoneNumber(phoneNumber);
        if (destination is null)
        {
            return false;
        }

        await _capture.CaptureSms(InferPurpose(messageBody), destination, messageBody);
        return true;
    }

    private static string? NormalizeTestPhoneNumber(string phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            return null;
        }

        string trimmed = phoneNumber.Trim();
        if (trimmed.StartsWith('+'))
        {
            return trimmed;
        }

        return trimmed.StartsWith("1", StringComparison.Ordinal)
            ? $"+{trimmed}"
            : $"+1{trimmed}";
    }

    private static string InferPurpose(string messageBody)
    {
        if (messageBody.Contains("password reset", StringComparison.OrdinalIgnoreCase))
        {
            return "password_reset";
        }

        if (messageBody.Contains("unlock", StringComparison.OrdinalIgnoreCase))
        {
            return "account_unlock";
        }

        return "sms_message";
    }
}
