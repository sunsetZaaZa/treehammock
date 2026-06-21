using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;

using treehammock.Rigging.Config;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace treehammock.Services;

public interface ISMTPService
{
    Task<bool?> VerificationLetter(string userEmailAddress, string subject, string verificationUrl);
    Task<bool?> ResendVerifyLetter(string userEmailAddress, string subject, string verificationUrl);
    Task<bool?> EmailChangeVerifyLetter(string userEmailAddress, string subject, string verificationUrl);
    Task<bool?> DeleteAccountTwoStepLetter(string userEmailAddress, string subject, string verificationUrl, string verifySequence);
    Task<bool?> AccountUnlockLetter(string userEmailAddress, string subject, string unlockToken);
    Task<bool?> TwoFactorSetupLetter(string userEmailAddress, string subject, string verifyKey);
    Task<bool?> TwoFactorKeyOutboundLetter(string userEmailAddress, string subject, string verifyKey);
    Task<bool?> TwoFactorDeleteLetter(string userEmailAddress, string subject, string verifyKey);
    Task<bool?> PasswordResetCodeLetter(string userEmailAddress, string subject, string keyCode, string expiresAt, string destinationMasked);
    Task<bool?> Send(string userEmailAddress, string subject, string body);
}

public class SMTPService : ISMTPService
{
    private readonly SMTPSettings _smtpSettings;
    private readonly ILogger<SMTPService> _logger;

    private readonly string _verificationTemplate;
    private readonly string _verificationResendTemplate;
    private readonly string _emailChangeVerifyTemplate;
    private readonly string _accountDeleteVerifyTemplate;
    private readonly string _accountUnlockTemplate;
    private readonly string _twoFactorSetupTemplate;
    private readonly string _twoFactorKeyOutboundTemplate;
    private readonly string _twoFactorDeleteTemplate;
    private readonly string _passwordResetCodeTemplate;
    
    public SMTPService(
        IOptions<SMTPSettings> smtpSettings,
        IOptions<EmailTemplateSettings> emailTemplateSettings,
        ILogger<SMTPService> logger)
    {
        _smtpSettings = smtpSettings.Value;
        _logger = logger;
        var templates = emailTemplateSettings.Value;

        _verificationTemplate = LoadTemplate(templates.AccountVerify, "<p>Verify your account: <a href='%verifyUrl'>%verifyUrl</a></p>");
        _verificationResendTemplate = LoadTemplate(templates.AccountVerifyResend, "<p>Verify your account: <a href='%verifyUrl'>%verifyUrl</a></p>");
        _emailChangeVerifyTemplate = LoadTemplate(templates.AccountEmailChangeVerify, "<p>Confirm your new email address: <a href='%verifyUrl'>%verifyUrl</a></p>");
        _accountDeleteVerifyTemplate = LoadTemplate(templates.AccountDeleteVerify, "<p>Confirm account deletion: <a href='%verifyUrl'>%verifyUrl</a></p><p>Verification code: %verifySequence</p>");
        _accountUnlockTemplate = LoadTemplate(templates.AccountUnlock, "<p>Your account unlock code is: %verifySequence</p>");
        _twoFactorSetupTemplate = LoadTemplate(templates.TwoFactorSetup, "<p>Confirm two-factor setup: %verifySequence</p>");
        _twoFactorKeyOutboundTemplate = LoadTemplate(templates.TwoFactorKeyOutbound, "<p>Your two-factor code is: %verifySequence</p>");
        _twoFactorDeleteTemplate = LoadTemplate(templates.TwoFactorDelete, "<p>Confirm two-factor removal: %verifySequence</p>");
        _passwordResetCodeTemplate = LoadTemplate(templates.PasswordResetCode, "<p>Your password reset code is: %verifySequence</p><p>It expires at %expiresAt.</p><p>Do not share this code.</p>");
    }

    private static string ApplyVerificationTemplate(string template, string verificationUrl)
    {
        return template
            .Replace("%verifyUrl", verificationUrl)
            .Replace("%verifySequence", verificationUrl);
    }

    private static string ApplySequenceTemplate(string template, string verifySequence)
    {
        return template.Replace("%verifySequence", verifySequence);
    }

    private static string ApplyDeleteVerifyTemplate(string template, string verificationUrl, string verifySequence)
    {
        return template
            .Replace("%verifyUrl", verificationUrl)
            .Replace("%verifySequence", verifySequence);
    }

    private static string ApplyPasswordResetTemplate(string template, string keyCode, string expiresAt, string destinationMasked)
    {
        return template
            .Replace("%verifySequence", keyCode)
            .Replace("%keyCode", keyCode)
            .Replace("%expiresAt", expiresAt)
            .Replace("%destinationMasked", destinationMasked);
    }

    private static string LoadTemplate(string configuredPath, string fallback)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return fallback;
        }

        string rootedPath = Path.IsPathRooted(configuredPath)
            ? configuredPath
            : Path.Combine(AppContext.BaseDirectory, configuredPath);

        if (!File.Exists(rootedPath))
        {
            rootedPath = Path.Combine(Directory.GetCurrentDirectory(), configuredPath);
        }

        return File.Exists(rootedPath)
            ? File.ReadAllText(rootedPath)
            : fallback;
    }

    private async Task<bool?> SendTemplatedMessage(string userEmailAddress, string subject, string body, string emailKind)
    {
        var email = new MimeMessage();
        email.From.Add(MailboxAddress.Parse(_smtpSettings.NoReplyEmailAddress));
        email.To.Add(MailboxAddress.Parse(userEmailAddress));
        email.Subject = subject;
        email.Body = new TextPart(TextFormat.Html) { Text = body };

        using var smtp = new SmtpClient();
        try
        {
            await smtp.ConnectAsync(_smtpSettings.SMTPQualifiedDomain, _smtpSettings.SMTPPort, SecureSocketOptions.None);
            await smtp.AuthenticateAsync(_smtpSettings.SMTPUsername, _smtpSettings.SMTPPassword);
            await smtp.SendAsync(email);
            await smtp.DisconnectAsync(true);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "SMTP delivery failed for {EmailKind} email to {RecipientDomain}.",
                emailKind,
                GetRecipientDomain(userEmailAddress));
            return null;
        }
    }

    private static string GetRecipientDomain(string userEmailAddress)
    {
        int atIndex = userEmailAddress.LastIndexOf('@');
        return atIndex >= 0 && atIndex < userEmailAddress.Length - 1
            ? userEmailAddress[(atIndex + 1)..]
            : "unknown";
    }

    public async Task<bool?> VerificationLetter(string userEmailAddress, string subject, string verificationUrl)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyVerificationTemplate(_verificationTemplate, verificationUrl),
            nameof(VerificationLetter));
    }

    public async Task<bool?> ResendVerifyLetter(string userEmailAddress, string subject, string verificationUrl)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyVerificationTemplate(_verificationResendTemplate, verificationUrl),
            nameof(ResendVerifyLetter));
    }

    public async Task<bool?> EmailChangeVerifyLetter(string userEmailAddress, string subject, string verificationUrl)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyVerificationTemplate(_emailChangeVerifyTemplate, verificationUrl),
            nameof(EmailChangeVerifyLetter));
    }

    public async Task<bool?> DeleteAccountTwoStepLetter(string userEmailAddress, string subject, string verificationUrl, string verifySequence)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyDeleteVerifyTemplate(_accountDeleteVerifyTemplate, verificationUrl, verifySequence),
            nameof(DeleteAccountTwoStepLetter));
    }

    public async Task<bool?> AccountUnlockLetter(string userEmailAddress, string subject, string unlockToken)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_accountUnlockTemplate, unlockToken),
            nameof(AccountUnlockLetter));
    }

    public async Task<bool?> TwoFactorSetupLetter(string userEmailAddress, string subject, string verifyKey)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_twoFactorSetupTemplate, verifyKey),
            nameof(TwoFactorSetupLetter));
    }

    public async Task<bool?> TwoFactorKeyOutboundLetter(string userEmailAddress, string subject, string verifyKey)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_twoFactorKeyOutboundTemplate, verifyKey),
            nameof(TwoFactorKeyOutboundLetter));
    }

    public async Task<bool?> TwoFactorDeleteLetter(string userEmailAddress, string subject, string verifyKey)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplySequenceTemplate(_twoFactorDeleteTemplate, verifyKey),
            nameof(TwoFactorDeleteLetter));
    }

    public async Task<bool?> PasswordResetCodeLetter(string userEmailAddress, string subject, string keyCode, string expiresAt, string destinationMasked)
    {
        return await SendTemplatedMessage(
            userEmailAddress,
            subject,
            ApplyPasswordResetTemplate(_passwordResetCodeTemplate, keyCode, expiresAt, destinationMasked),
            nameof(PasswordResetCodeLetter));
    }

    public async Task<bool?> Send(string userEmailAddress, string subject, string body)
    {
        return await SendTemplatedMessage(userEmailAddress, subject, body, nameof(Send));
    }
}
