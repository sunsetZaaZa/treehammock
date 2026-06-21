using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.Models.PasswordReset;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;

namespace treehammock.Services;

public sealed record PasswordResetDeliveryCommand(
    Guid ResetId,
    Guid AccountId,
    string Method,
    string DeliveryChannel,
    string DestinationMasked,
    string DestinationAddressOrPhone,
    string KeyCode,
    Instant ExpiresAt,
    string? RequestIpAddress = null);

public sealed record PasswordResetDeliveryResult(bool Sent, string Code);

public interface IPasswordResetDeliveryService
{
    Task<PasswordResetDeliveryResult> SendPasswordResetCode(
        PasswordResetDeliveryCommand command,
        CancellationToken cancellationToken);
}

public sealed class PasswordResetDeliveryService : IPasswordResetDeliveryService
{
    public const string SentCode = "PASSWORD_RESET_DELIVERY_SENT";
    public const string FailedCode = "PASSWORD_RESET_DELIVERY_FAILED";
    public const string UnsupportedDeliveryChannelCode = "PASSWORD_RESET_DELIVERY_UNSUPPORTED_CHANNEL";

    private readonly ISMTPService _smtpService;
    private readonly ISmsSender _smsSender;
    private readonly EmailSubjectSettings _emailSubjectSettings;
    private readonly string _smsTemplate;
    private readonly ILogger<PasswordResetDeliveryService> _logger;
    private readonly IDeliveryAbuseThrottleService _deliveryAbuseThrottleService;

    public PasswordResetDeliveryService(
        ISMTPService smtpService,
        ISmsSender smsSender,
        IOptions<EmailSubjectSettings> emailSubjectSettings,
        IOptions<EmailTemplateSettings> emailTemplateSettings,
        ILogger<PasswordResetDeliveryService> logger,
        IDeliveryAbuseThrottleService? deliveryAbuseThrottleService = null)
    {
        _smtpService = smtpService;
        _smsSender = smsSender;
        _emailSubjectSettings = emailSubjectSettings.Value;
        _logger = logger;
        _deliveryAbuseThrottleService = deliveryAbuseThrottleService ?? NullDeliveryAbuseThrottleService.Instance;

        EmailTemplateSettings templates = emailTemplateSettings.Value;
        _smsTemplate = LoadTemplate(
            templates.PasswordResetSmsCode,
            "Your Treehammock password reset code is %verifySequence. It expires at %expiresAt. Do not share this code.");
    }

    public async Task<PasswordResetDeliveryResult> SendPasswordResetCode(
        PasswordResetDeliveryCommand command,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            return command.DeliveryChannel.Trim().ToLowerInvariant() switch
            {
                "email" => await SendEmail(command),
                "sms" => await SendSms(command),
                _ => new PasswordResetDeliveryResult(false, UnsupportedDeliveryChannelCode)
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Password reset code delivery failed for channel {DeliveryChannel} and masked destination {DestinationMasked}.",
                command.DeliveryChannel,
                command.DestinationMasked);
            return new PasswordResetDeliveryResult(false, FailedCode);
        }
    }

    private async Task<PasswordResetDeliveryResult> SendEmail(PasswordResetDeliveryCommand command)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.PasswordResetRequest, "email", command.AccountId, DeliveryAbuseThrottleService.SafeDestination("email", command.DestinationAddressOrPhone));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return new PasswordResetDeliveryResult(false, FailedCode);
        }

        bool? sent;
        try
        {
            sent = await _smtpService.PasswordResetCodeLetter(
                command.DestinationAddressOrPhone,
                _emailSubjectSettings.PasswordResetCode,
                command.KeyCode,
                FormatExpiration(command.ExpiresAt),
                command.DestinationMasked);
        }
        catch
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            throw;
        }

        if (sent == true)
        {
            return new PasswordResetDeliveryResult(true, SentCode);
        }

        await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
        _logger.LogWarning(
            "Password reset email delivery failed for recipient domain {RecipientDomain}.",
            RecipientDomain(command.DestinationAddressOrPhone));
        return new PasswordResetDeliveryResult(false, FailedCode);
    }

    private async Task<PasswordResetDeliveryResult> SendSms(PasswordResetDeliveryCommand command)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.PasswordResetRequest, "sms", command.AccountId, DeliveryAbuseThrottleService.SafeDestination("sms", command.DestinationAddressOrPhone));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return new PasswordResetDeliveryResult(false, FailedCode);
        }

        string body = ApplySmsTemplate(
            _smsTemplate,
            command.KeyCode,
            FormatExpiration(command.ExpiresAt),
            command.DestinationMasked);

        bool sent;
        try
        {
            sent = await _smsSender.SendMessage(command.DestinationAddressOrPhone, body);
        }
        catch
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            throw;
        }

        if (sent)
        {
            return new PasswordResetDeliveryResult(true, SentCode);
        }

        await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
        _logger.LogWarning("Password reset SMS delivery failed for masked destination {DestinationMasked}.", command.DestinationMasked);
        return new PasswordResetDeliveryResult(false, FailedCode);
    }

    private static string ApplySmsTemplate(string template, string keyCode, string expiresAt, string destinationMasked)
    {
        return template
            .Replace("%verifySequence", keyCode)
            .Replace("%keyCode", keyCode)
            .Replace("%expiresAt", expiresAt)
            .Replace("%destinationMasked", destinationMasked);
    }

    private static string FormatExpiration(Instant expiresAt)
    {
        return expiresAt
            .ToDateTimeOffset()
            .ToUniversalTime()
            .ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
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

    private static string RecipientDomain(string emailAddress)
    {
        int atIndex = emailAddress.LastIndexOf('@');
        return atIndex >= 0 && atIndex < emailAddress.Length - 1
            ? emailAddress[(atIndex + 1)..]
            : "unknown";
    }
}
