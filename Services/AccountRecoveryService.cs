using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.Models.Recovery;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Services;

public sealed record AccountRecoveryStartResult(bool Result, string Code);
public sealed record AccountRecoveryVerifyResult(bool Result, string Code);

public interface IAccountRecoveryService
{
    Task<AccountRecoveryStartResult> StartRecovery(AccountRecoveryRequest request, Instant createdOn);
    Task<AccountRecoveryVerifyResult> VerifyRecovery(AccountRecoveryVerifyRequest request);
}

/// <summary>
/// Account recovery is the account-unlock flow for accounts that have reached the password-attempt lockout threshold.
/// It is not a password-reset, username-recovery, or MFA-reset feature.
/// </summary>
public class AccountRecoveryService : IAccountRecoveryService
{
    public const string PendingCode = "ACCOUNT_UNLOCK_PENDING";
    public const string VerifiedCode = "ACCOUNT_UNLOCK_VERIFIED";
    public const string TokenExpiredCode = "ACCOUNT_UNLOCK_TOKEN_EXPIRED";
    public const string TokenMismatchCode = "ACCOUNT_UNLOCK_TOKEN_MISMATCH";
    public const string FailedCode = "ACCOUNT_UNLOCK_FAILED";
    public const string NotLockedCode = "ACCOUNT_UNLOCK_NOT_LOCKED";

    private const int RecoveryTokenByteLength = 32;

    private readonly IAccountRecoveryRepo _accountRecoveryRepo;
    private readonly ISMTPService _smtpService;
    private readonly ISmsSender _smsSender;
    private readonly EmailSubjectSettings _emailSubjectSettings;
    private readonly ILogger<AccountRecoveryService> _logger;
    private readonly IDeliveryAbuseThrottleService _deliveryAbuseThrottleService;
    private readonly IAccountUnlockAbuseCounterKeyFactory _accountUnlockAbuseCounterKeyFactory;
    private readonly IAbuseCounterStore? _abuseCounterStore;
    private readonly AbuseControlSettings _abuseControlSettings;
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public AccountRecoveryService(
        IAccountRecoveryRepo accountRecoveryRepo,
        ISMTPService smtpService,
        ISmsSender smsSender,
        IOptions<EmailSubjectSettings>? emailSubjectSettings,
        ILogger<AccountRecoveryService> logger,
        IDeliveryAbuseThrottleService? deliveryAbuseThrottleService = null,
        IAccountUnlockAbuseCounterKeyFactory? accountUnlockAbuseCounterKeyFactory = null,
        IAbuseCounterStore? abuseCounterStore = null,
        IOptions<AbuseControlSettings>? abuseControlSettings = null,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _accountRecoveryRepo = accountRecoveryRepo;
        _smtpService = smtpService;
        _smsSender = smsSender;
        _emailSubjectSettings = emailSubjectSettings?.Value ?? new EmailSubjectSettings();
        _logger = logger;
        _deliveryAbuseThrottleService = deliveryAbuseThrottleService ?? NullDeliveryAbuseThrottleService.Instance;
        _accountUnlockAbuseCounterKeyFactory = accountUnlockAbuseCounterKeyFactory ?? new AccountUnlockAbuseCounterKeyFactory();
        _abuseCounterStore = abuseCounterStore;
        _abuseControlSettings = abuseControlSettings?.Value ?? new AbuseControlSettings();
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<AccountRecoveryStartResult> StartRecovery(AccountRecoveryRequest request, Instant createdOn)
    {
        AccountRecoveryLookupResult? lookup = await _accountRecoveryRepo.LookupLockedAccount(NormalizeIdentifier(request.identifier), createdOn);
        if (lookup is null)
        {
            return new AccountRecoveryStartResult(false, FailedCode);
        }

        if (!lookup.Result
            || lookup.AccountId is null
            || lookup.AccountSecurityStamp is null
            || lookup.UnlockWhen is null
            || !HasDeliveryDestination(lookup, request.deliveryMethod))
        {
            // Keep unlock start responses generic so unknown, currently-unlocked, or non-deliverable accounts do not leak account state.
            return new AccountRecoveryStartResult(true, PendingCode);
        }

        string token = GenerateRecoveryToken();
        Instant expiration = createdOn.Plus(Duration.FromHours(1));

        AccountRecovery_Status? started = await _accountRecoveryRepo.BeginUnlock(
            lookup.AccountId.Value,
            token,
            createdOn,
            expiration,
            AccountRecovery_Status.STANDBY,
            request.deliveryMethod,
            lookup.AccountSecurityStamp.Value,
            lookup.UnlockWhen.Value);

        if (started is AccountRecovery_Status.NOT_LOCKED or AccountRecovery_Status.STALE_LOCKOUT)
        {
            // Preserve the generic start response even if the lockout state changes between lookup and persistence.
            return new AccountRecoveryStartResult(true, PendingCode);
        }

        if (started != AccountRecovery_Status.STANDBY)
        {
            return new AccountRecoveryStartResult(false, StartUnlockStatusCode(started));
        }

        bool delivered = await TryDeliverUnlockToken(lookup, request.deliveryMethod, token);
        if (delivered)
        {
            return new AccountRecoveryStartResult(true, PendingCode);
        }

        AccountRecovery_Status? cancelled = await _accountRecoveryRepo.CancelUnlock(lookup.AccountId.Value, token);
        if (cancelled != AccountRecovery_Status.CANCELED)
        {
            _logger.LogError(
                "Account unlock token cleanup failed for account {AccountId} after delivery failure.",
                lookup.AccountId.Value);
        }

        // Keep anonymous unlock-start responses generic so delivery or cleanup failures do not reveal
        // whether an identifier belongs to a locked account.
        return new AccountRecoveryStartResult(true, PendingCode);
    }

    public async Task<AccountRecoveryVerifyResult> VerifyRecovery(AccountRecoveryVerifyRequest request)
    {
        string token = request.token.Trim();
        AbuseDecision abuseDecision = await CheckUnlockVerifyAttemptPolicy(token);
        if (!abuseDecision.Allowed)
        {
            return new AccountRecoveryVerifyResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded);
        }

        AccountRecovery_Status? verified = await _accountRecoveryRepo.VerifyUnlock(token);
        if (verified == AccountRecovery_Status.COMPLETE)
        {
            await ResetUnlockVerifyAttemptPolicy(token);
            return new AccountRecoveryVerifyResult(true, VerifiedCode);
        }

        return new AccountRecoveryVerifyResult(false, UnlockStatusCode(verified));
    }


    private async Task<AbuseDecision> CheckUnlockVerifyAttemptPolicy(string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountUnlock.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.AccountUnlock.VerifyAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.AccountUnlock.CooldownSecondsAfterExhaustion);
        var tokenLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountUnlock.MaxVerifyAttemptsPerToken,
            window,
            cooldown);
        var ipLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountUnlock.MaxVerifyAttemptsPerIp,
            window,
            cooldown);

        AbuseDecision tokenDecision = await IncrementUnlockVerifyCounter(
            _accountUnlockAbuseCounterKeyFactory.ForVerifyToken(token),
            tokenLimit);
        if (!tokenDecision.Allowed)
        {
            return tokenDecision;
        }

        return await IncrementUnlockVerifyCounter(
            _accountUnlockAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()),
            ipLimit);
    }

    private async Task<AbuseDecision> IncrementUnlockVerifyCounter(
        AbuseCounterKey key,
        AbuseCounterLimit limit)
    {
        CounterDecision decision = await _abuseCounterStore!.IncrementAsync(key, limit);
        if (decision.Allowed)
        {
            return AbuseDecision.Allow();
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded;
        AbuseOperationalTelemetry.RecordPolicyDenied(key.Feature, key.Dimension, reasonCode);

        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);
    }

    private async Task ResetUnlockVerifyAttemptPolicy(string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountUnlock.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_accountUnlockAbuseCounterKeyFactory.ForVerifyToken(token));
        await _abuseCounterStore.ResetAsync(_accountUnlockAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()));
    }

    private string ResolveClientIpAddress()
    {
        IPAddress? remoteIp = _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress;
        return remoteIp?.ToString() ?? "unknown";
    }

    internal static string GenerateRecoveryToken()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(RecoveryTokenByteLength);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private async Task<bool> TryDeliverUnlockToken(
        AccountRecoveryLookupResult lookup,
        AccountUnlockDeliveryMethod deliveryMethod,
        string token)
    {
        try
        {
            return deliveryMethod switch
            {
                AccountUnlockDeliveryMethod.EMAIL => await TrySendUnlockEmail(lookup.AccountId, lookup.EmailAddress!, token),
                AccountUnlockDeliveryMethod.SMS => await TrySendUnlockSms(lookup.AccountId, BuildSmsDestination(lookup.PhoneCountryCode, lookup.PhoneNumber), token),
                _ => false
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Account unlock token delivery failed for {DeliveryMethod}.", deliveryMethod);
            return false;
        }
    }

    private async Task<bool> TrySendUnlockEmail(Guid? accountId, string emailAddress, string token)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.AccountUnlock, "email", accountId, DeliveryAbuseThrottleService.SafeDestination("email", emailAddress));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        bool? sent = await _smtpService.AccountUnlockLetter(emailAddress, _emailSubjectSettings.AccountUnlock, token);
        if (sent != true)
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            _logger.LogWarning("Account unlock email delivery failed for {RecipientDomain}.", RecipientDomain(emailAddress));
        }

        return sent == true;
    }

    private async Task<bool> TrySendUnlockSms(Guid? accountId, string? phoneNumber, string token)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            return false;
        }

        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.AccountUnlock, "sms", accountId, DeliveryAbuseThrottleService.SafeDestination("sms", phoneNumber));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        bool sent = await _smsSender.SendCode(phoneNumber, token);
        if (!sent)
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            _logger.LogWarning("Account unlock SMS delivery failed.");
        }

        return sent;
    }

    private static bool HasDeliveryDestination(AccountRecoveryLookupResult lookup, AccountUnlockDeliveryMethod deliveryMethod)
    {
        return deliveryMethod switch
        {
            AccountUnlockDeliveryMethod.EMAIL => !string.IsNullOrWhiteSpace(lookup.EmailAddress),
            AccountUnlockDeliveryMethod.SMS => !string.IsNullOrWhiteSpace(lookup.PhoneNumber),
            _ => false
        };
    }

    private static string? BuildSmsDestination(string? phoneCountryCode, string? phoneNumber)
    {
        if (string.IsNullOrWhiteSpace(phoneNumber))
        {
            return null;
        }

        string normalizedPhoneNumber = phoneNumber.Trim();
        if (normalizedPhoneNumber.StartsWith('+'))
        {
            return normalizedPhoneNumber;
        }

        string normalizedCountryCode = phoneCountryCode?.Trim().TrimStart('+') ?? string.Empty;
        return string.IsNullOrWhiteSpace(normalizedCountryCode)
            ? normalizedPhoneNumber
            : $"+{normalizedCountryCode}{normalizedPhoneNumber}";
    }

    private static string StartUnlockStatusCode(AccountRecovery_Status? status)
    {
        return status switch
        {
            AccountRecovery_Status.NOT_LOCKED => NotLockedCode,
            _ => FailedCode
        };
    }

    private static string UnlockStatusCode(AccountRecovery_Status? status)
    {
        return status switch
        {
            AccountRecovery_Status.EXPIRED => TokenExpiredCode,
            AccountRecovery_Status.BAD_TOKEN or AccountRecovery_Status.BAD_VERIFY or AccountRecovery_Status.STALE_LOCKOUT => TokenMismatchCode,
            AccountRecovery_Status.NOT_LOCKED => NotLockedCode,
            _ => FailedCode
        };
    }

    private static string NormalizeIdentifier(string identifier)
    {
        return identifier.Trim().ToLowerInvariant();
    }

    private static string RecipientDomain(string emailAddress)
    {
        int atIndex = emailAddress.LastIndexOf('@');
        return atIndex >= 0 && atIndex < emailAddress.Length - 1
            ? emailAddress[(atIndex + 1)..]
            : "unknown";
    }
}
