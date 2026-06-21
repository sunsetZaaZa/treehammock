using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using Microsoft.Extensions.Options;

namespace treehammock.Services;

public interface ITwoFactorAuthenticateService
{
    Task<bool> Email(string emailAddress, string codeKey, Guid? accountId = null);
    Task<bool> SetupEmail(string emailAddress, string codeKey, Guid? accountId = null);
    Task<bool?> SMS(string phonenumber, string codeKey, Guid? accountId = null);
    Task<bool?> SetupSMS(string phoneNumber, string codeKey, Guid? accountId = null);
}

public class TwoFactorAuthenticateService : ITwoFactorAuthenticateService
{
    private readonly ISMTPService _smtpService;
    private readonly ISmsSender _smsSender;
    private readonly EmailSubjectSettings _emailSubjectSettings;
    private readonly IDeliveryAbuseThrottleService _deliveryAbuseThrottleService;

    public TwoFactorAuthenticateService(
        ISMTPService smtpService,
        ISmsSender smsSender,
        IOptions<EmailSubjectSettings>? emailSubjectSettings = null,
        IDeliveryAbuseThrottleService? deliveryAbuseThrottleService = null)
    {
        _smtpService = smtpService;
        _smsSender = smsSender;
        _emailSubjectSettings = emailSubjectSettings?.Value ?? new EmailSubjectSettings();
        _deliveryAbuseThrottleService = deliveryAbuseThrottleService ?? NullDeliveryAbuseThrottleService.Instance;
    }


    public async Task<bool> Email(string emailAddress, string codeKey, Guid? accountId = null)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.Delivery, "email", accountId, DeliveryAbuseThrottleService.SafeDestination("email", emailAddress));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            bool? sent = await _smtpService.TwoFactorKeyOutboundLetter(emailAddress, _emailSubjectSettings.TwoFactorKeyOutbound, codeKey);
            if (sent != true)
            {
                await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            }

            return sent == true;
        }
        catch
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            throw;
        }
    }

    public async Task<bool> SetupEmail(string emailAddress, string codeKey, Guid? accountId = null)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.Delivery, "email", accountId, DeliveryAbuseThrottleService.SafeDestination("email", emailAddress));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            bool? sent = await _smtpService.TwoFactorSetupLetter(emailAddress, _emailSubjectSettings.TwoFactorSetup, codeKey);
            if (sent != true)
            {
                await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            }

            return sent == true;
        }
        catch
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            throw;
        }
    }

    public async Task<bool?> SMS(string phonenumber, string codeKey, Guid? accountId = null)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.Delivery, "sms", accountId, DeliveryAbuseThrottleService.SafeDestination("sms", phonenumber));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            bool sent = _smsSender is ISystemTestPurposeAwareSmsSender systemTestSender
                ? await systemTestSender.SendCode(phonenumber, codeKey, "two_factor_login")
                : await _smsSender.SendCode(phonenumber, codeKey);
            if (!sent)
            {
                await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            }

            return sent;
        }
        catch
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            throw;
        }
    }

    public async Task<bool?> SetupSMS(string phoneNumber, string codeKey, Guid? accountId = null)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.Delivery, "sms", accountId, DeliveryAbuseThrottleService.SafeDestination("sms", phoneNumber));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            bool sent = _smsSender is ISystemTestPurposeAwareSmsSender systemTestSender
                ? await systemTestSender.SendCode(phoneNumber, codeKey, "two_factor_setup")
                : await _smsSender.SendCode(phoneNumber, codeKey);
            if (!sent)
            {
                await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            }

            return sent;
        }
        catch
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            throw;
        }
    }
}
