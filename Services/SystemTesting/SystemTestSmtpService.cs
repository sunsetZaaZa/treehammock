using treehammock.Services.SystemTesting;

namespace treehammock.Services;

public sealed class SystemTestSmtpService : ISMTPService
{
    private readonly ISystemTestDeliveryCapture _capture;

    public SystemTestSmtpService(ISystemTestDeliveryCapture capture)
    {
        _capture = capture;
    }

    public async Task<bool?> VerificationLetter(string userEmailAddress, string subject, string verificationUrl)
    {
        await _capture.CaptureEmail("account_verify", userEmailAddress, subject, BuildVerificationBody(verificationUrl), ExtractVerificationPayload(verificationUrl));
        return true;
    }

    public async Task<bool?> ResendVerifyLetter(string userEmailAddress, string subject, string verificationUrl)
    {
        await _capture.CaptureEmail("account_verify", userEmailAddress, subject, BuildVerificationBody(verificationUrl), ExtractVerificationPayload(verificationUrl));
        return true;
    }

    public async Task<bool?> EmailChangeVerifyLetter(string userEmailAddress, string subject, string verificationUrl)
    {
        await _capture.CaptureEmail("email_change", userEmailAddress, subject, BuildVerificationBody(verificationUrl), ExtractVerificationPayload(verificationUrl));
        return true;
    }

    public async Task<bool?> DeleteAccountTwoStepLetter(string userEmailAddress, string subject, string verificationUrl, string verifySequence)
    {
        await _capture.CaptureEmail("account_delete", userEmailAddress, subject, $"Confirm account deletion: {verificationUrl}\nCode: {verifySequence}", verifySequence);
        return true;
    }

    public async Task<bool?> AccountUnlockLetter(string userEmailAddress, string subject, string unlockToken)
    {
        await _capture.CaptureEmail("account_unlock", userEmailAddress, subject, $"Unlock token: {unlockToken}", unlockToken);
        return true;
    }

    public async Task<bool?> TwoFactorSetupLetter(string userEmailAddress, string subject, string verifyKey)
    {
        await _capture.CaptureEmail("two_factor_setup", userEmailAddress, subject, $"Two-factor setup code: {verifyKey}", verifyKey);
        return true;
    }

    public async Task<bool?> TwoFactorKeyOutboundLetter(string userEmailAddress, string subject, string verifyKey)
    {
        await _capture.CaptureEmail("two_factor_login", userEmailAddress, subject, $"Two-factor login code: {verifyKey}", verifyKey);
        return true;
    }

    public async Task<bool?> TwoFactorDeleteLetter(string userEmailAddress, string subject, string verifyKey)
    {
        await _capture.CaptureEmail("two_factor_delete", userEmailAddress, subject, $"Two-factor delete code: {verifyKey}", verifyKey);
        return true;
    }

    public async Task<bool?> PasswordResetCodeLetter(string userEmailAddress, string subject, string keyCode, string expiresAt, string destinationMasked)
    {
        await _capture.CaptureEmail("password_reset", userEmailAddress, subject, $"Password reset code: {keyCode}\nExpires at: {expiresAt}\nDestination: {destinationMasked}", keyCode);
        return true;
    }

    public async Task<bool?> Send(string userEmailAddress, string subject, string body)
    {
        string purpose = subject.Contains("activation", StringComparison.OrdinalIgnoreCase)
            ? "activation"
            : "email";
        await _capture.CaptureEmail(purpose, userEmailAddress, subject, body);
        return true;
    }

    private static string BuildVerificationBody(string verificationUrl) => $"Verify account: {verificationUrl}";

    private static string? ExtractVerificationPayload(string verificationUrl)
    {
        int marker = verificationUrl.IndexOf("payload=", StringComparison.OrdinalIgnoreCase);
        if (marker < 0)
        {
            return null;
        }

        string payload = verificationUrl[(marker + "payload=".Length)..];
        int separator = payload.IndexOfAny(new[] { '&', '#', ' ', '\r', '\n' });
        if (separator >= 0)
        {
            payload = payload[..separator];
        }

        return Uri.UnescapeDataString(payload);
    }
}
