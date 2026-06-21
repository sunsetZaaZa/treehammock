using Amazon.Runtime;
using Amazon.SimpleNotificationService;
using Amazon.SimpleNotificationService.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;

namespace treehammock.Rigging.Sidewalk;

public interface IAwsSnsSmsClient
{
    Task<string?> PublishSms(string phoneNumber, string body);
}

public sealed class AwsSnsSmsClient : IAwsSnsSmsClient
{
    public async Task<string?> PublishSms(string phoneNumber, string body)
    {
        using var client = new AmazonSimpleNotificationServiceClient();
        var response = await client.PublishAsync(new PublishRequest
        {
            PhoneNumber = phoneNumber,
            Message = body
        });

        return response.MessageId;
    }
}

public interface IAWSService
{
    Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey);
    Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody);
}

public class AWSService : IAWSService
{
    private const string ProviderName = "aws-sns";

    private readonly IAwsSnsSmsClient _client;
    private readonly SidewalkSettings _settings;
    private readonly ILogger<AWSService> _logger;

    public AWSService(
        IAwsSnsSmsClient client,
        IOptions<SidewalkSettings> settings,
        ILogger<AWSService>? logger = null)
    {
        _client = client;
        _settings = settings.Value;
        _logger = logger ?? NullLogger<AWSService>.Instance;
    }

    public async Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey)
    {
        return await SendMessage(phoneNumber, $"Your Treehammock security code is {codeKey}.");
    }

    public async Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody)
    {
        if (!_settings.SmsEnabled || !_settings.AwsSnsEnabled)
        {
            return ProviderDeliveryResult.Disabled(ProviderName);
        }

        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            return ProviderDeliveryResult.InvalidRequest(ProviderName, "PHONE_NUMBER_REQUIRED");
        }

        if (string.IsNullOrWhiteSpace(messageBody))
        {
            return ProviderDeliveryResult.InvalidRequest(ProviderName, "BODY_REQUIRED");
        }

        try
        {
            string? messageId = await _client.PublishSms(
                phoneNumber,
                messageBody);

            return string.IsNullOrWhiteSpace(messageId)
                ? ProviderDeliveryResult.Failed(ProviderName, "EMPTY_PROVIDER_MESSAGE_ID")
                : ProviderDeliveryResult.Sent(ProviderName, messageId);
        }
        catch (AmazonServiceException ex) when ((int)ex.StatusCode == 429 || IsThrottleError(ex.ErrorCode))
        {
            _logger.LogWarning(ex, "AWS SNS SMS delivery was rate limited by the provider.");
            return ProviderDeliveryResult.RateLimited(ProviderName, ex.ErrorCode);
        }
        catch (AmazonServiceException ex) when ((int)ex.StatusCode is >= 400 and < 500)
        {
            _logger.LogWarning(ex, "AWS SNS SMS delivery was rejected by the provider with code {ProviderErrorCode}.", ex.ErrorCode);
            return ProviderDeliveryResult.Rejected(ProviderName, ex.ErrorCode);
        }
        catch (AmazonServiceException ex)
        {
            _logger.LogWarning(ex, "AWS SNS SMS delivery failed with provider error code {ProviderErrorCode}.", ex.ErrorCode);
            return ProviderDeliveryResult.ProviderUnavailable(ProviderName, ex.ErrorCode);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "AWS SNS SMS delivery failed unexpectedly.");
            return ProviderDeliveryResult.Failed(ProviderName);
        }
    }

    private static bool IsThrottleError(string? errorCode) =>
        !string.IsNullOrWhiteSpace(errorCode) &&
        errorCode.Contains("throttl", StringComparison.OrdinalIgnoreCase);
}
