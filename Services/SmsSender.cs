using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;
using treehammock.Rigging.Sidewalk;

namespace treehammock.Services;

public interface ISmsSender
{
    Task<bool> SendCode(string phoneNumber, string codeKey);
    Task<bool> SendMessage(string phoneNumber, string messageBody);
}

public class SmsSender : ISmsSender
{
    private readonly IAWSService _awsService;
    private readonly ITwilioSmsService _twilioSmsService;
    private readonly SidewalkSettings _settings;
    private readonly ILogger<SmsSender> _logger;

    public SmsSender(
        IAWSService awsService,
        ITwilioSmsService twilioSmsService,
        IOptions<SidewalkSettings> settings,
        ILogger<SmsSender>? logger = null)
    {
        _awsService = awsService;
        _twilioSmsService = twilioSmsService;
        _settings = settings.Value;
        _logger = logger ?? NullLogger<SmsSender>.Instance;
    }

    public async Task<bool> SendCode(string phoneNumber, string codeKey)
    {
        return await Send(phoneNumber, codeKey, sendRawMessage: false);
    }

    public async Task<bool> SendMessage(string phoneNumber, string messageBody)
    {
        return await Send(phoneNumber, messageBody, sendRawMessage: true);
    }

    private async Task<bool> Send(string phoneNumber, string bodyOrCode, bool sendRawMessage)
    {
        if (!_settings.SmsEnabled)
        {
            _logger.LogInformation("SMS delivery requested while SMS is disabled.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(phoneNumber) || string.IsNullOrWhiteSpace(bodyOrCode))
        {
            _logger.LogWarning("SMS delivery requested with missing destination or body.");
            return false;
        }

        foreach (string provider in Providers())
        {
            ProviderDeliveryResult result = await SendWithProvider(provider, phoneNumber, bodyOrCode, sendRawMessage);
            if (result.Succeeded)
            {
                _logger.LogInformation("SMS delivery succeeded with provider {Provider}.", result.Provider);
                return true;
            }

            _logger.LogWarning(
                "SMS delivery provider {Provider} did not send the message. Status: {Status}; Code: {FailureCode}.",
                result.Provider,
                result.Status,
                result.FailureCode);
        }

        return false;
    }

    private async Task<ProviderDeliveryResult> SendWithProvider(string provider, string phoneNumber, string bodyOrCode, bool sendRawMessage)
    {
        try
        {
            return SmsProviderNames.Normalize(provider) switch
            {
                SmsProviderNames.AwsSns => _settings.AwsSnsEnabled
                    ? sendRawMessage
                        ? await _awsService.SendMessage(phoneNumber, bodyOrCode)
                        : await _awsService.SendSMS(phoneNumber, bodyOrCode)
                    : ProviderDeliveryResult.Disabled(SmsProviderNames.AwsSns),
                SmsProviderNames.Twilio => _settings.TwilioEnabled
                    ? sendRawMessage
                        ? await _twilioSmsService.SendMessage(phoneNumber, bodyOrCode)
                        : await _twilioSmsService.SendSMS(phoneNumber, bodyOrCode)
                    : ProviderDeliveryResult.Disabled(SmsProviderNames.Twilio),
                _ => ProviderDeliveryResult.InvalidRequest(provider, "UNKNOWN_SMS_PROVIDER")
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SMS delivery provider {Provider} failed unexpectedly.", provider);
            return ProviderDeliveryResult.Failed(provider);
        }
    }

    private IEnumerable<string> Providers()
    {
        foreach (string provider in SmsProviderNames.NormalizeConfiguredProviders(_settings).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            yield return provider;
        }
    }
}

public interface ITwilioMessageClient
{
    Task<ProviderDeliveryResult> SendMessage(
        string accountSid,
        string authToken,
        string fromPhoneNumber,
        string toPhoneNumber,
        string body);
}

public sealed class TwilioMessageClient : ITwilioMessageClient
{
    private const string ProviderName = "twilio";
    private readonly IHttpClientFactory _httpClientFactory;

    public TwilioMessageClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<ProviderDeliveryResult> SendMessage(
        string accountSid,
        string authToken,
        string fromPhoneNumber,
        string toPhoneNumber,
        string body)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            $"https://api.twilio.com/2010-04-01/Accounts/{Uri.EscapeDataString(accountSid)}/Messages.json");

        string encodedCredentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{accountSid}:{authToken}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", encodedCredentials);
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["From"] = fromPhoneNumber,
            ["To"] = toPhoneNumber,
            ["Body"] = body
        });

        HttpClient httpClient = _httpClientFactory.CreateClient("treehammock-twilio");
        using HttpResponseMessage response = await httpClient.SendAsync(request);

        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            return ProviderDeliveryResult.RateLimited(ProviderName, ((int)response.StatusCode).ToString());
        }

        if ((int)response.StatusCode is >= 400 and < 500)
        {
            return ProviderDeliveryResult.Rejected(ProviderName, await ReadProviderError(response));
        }

        if ((int)response.StatusCode >= 500)
        {
            return ProviderDeliveryResult.ProviderUnavailable(ProviderName, ((int)response.StatusCode).ToString());
        }

        string responseBody = await response.Content.ReadAsStringAsync();
        string? sid = TryReadSid(responseBody);
        return string.IsNullOrWhiteSpace(sid)
            ? ProviderDeliveryResult.Failed(ProviderName, "EMPTY_PROVIDER_MESSAGE_ID")
            : ProviderDeliveryResult.Sent(ProviderName, sid);
    }

    private static async Task<string> ReadProviderError(HttpResponseMessage response)
    {
        string body = await response.Content.ReadAsStringAsync();
        return TryReadErrorCode(body) ?? ((int)response.StatusCode).ToString();
    }

    private static string? TryReadSid(string responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(responseBody);
            return document.RootElement.TryGetProperty("sid", out JsonElement sid)
                ? sid.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? TryReadErrorCode(string responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return null;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(responseBody);
            if (document.RootElement.TryGetProperty("code", out JsonElement code))
            {
                return code.ValueKind == JsonValueKind.Number
                    ? code.GetInt32().ToString()
                    : code.GetString();
            }
        }
        catch (JsonException)
        {
            return null;
        }

        return null;
    }
}

public interface ITwilioSmsService
{
    Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey);
    Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody);
}

public class TwilioSmsService : ITwilioSmsService
{
    private const string ProviderName = "twilio";

    private readonly ITwilioMessageClient _client;
    private readonly SidewalkSettings _settings;
    private readonly ILogger<TwilioSmsService> _logger;

    public TwilioSmsService(
        ITwilioMessageClient client,
        IOptions<SidewalkSettings> settings,
        ILogger<TwilioSmsService>? logger = null)
    {
        _client = client;
        _settings = settings.Value;
        _logger = logger ?? NullLogger<TwilioSmsService>.Instance;
    }

    public async Task<ProviderDeliveryResult> SendSMS(string phoneNumber, string codeKey)
    {
        return await SendMessage(phoneNumber, $"Your Treehammock security code is {codeKey}.");
    }

    public async Task<ProviderDeliveryResult> SendMessage(string phoneNumber, string messageBody)
    {
        if (!_settings.SmsEnabled || !_settings.TwilioEnabled)
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

        if (string.IsNullOrWhiteSpace(_settings.TwilioAccountSid))
        {
            return ProviderDeliveryResult.ConfigurationMissing(ProviderName, nameof(SidewalkSettings.TwilioAccountSid));
        }

        if (string.IsNullOrWhiteSpace(_settings.TwilioAuthToken))
        {
            return ProviderDeliveryResult.ConfigurationMissing(ProviderName, nameof(SidewalkSettings.TwilioAuthToken));
        }

        if (string.IsNullOrWhiteSpace(_settings.TwilioFromPhoneNumber))
        {
            return ProviderDeliveryResult.ConfigurationMissing(ProviderName, nameof(SidewalkSettings.TwilioFromPhoneNumber));
        }

        try
        {
            ProviderDeliveryResult result = await _client.SendMessage(
                _settings.TwilioAccountSid,
                _settings.TwilioAuthToken,
                _settings.TwilioFromPhoneNumber,
                phoneNumber,
                messageBody);

            if (!result.Succeeded)
            {
                _logger.LogWarning(
                    "Twilio SMS delivery did not send the message. Status: {Status}; Code: {FailureCode}.",
                    result.Status,
                    result.FailureCode);
            }

            return result;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "Twilio SMS delivery could not reach the provider.");
            return ProviderDeliveryResult.ProviderUnavailable(ProviderName);
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogWarning(ex, "Twilio SMS delivery timed out.");
            return ProviderDeliveryResult.ProviderUnavailable(ProviderName, "TIMEOUT");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Twilio SMS delivery failed unexpectedly.");
            return ProviderDeliveryResult.Failed(ProviderName);
        }
    }
}
