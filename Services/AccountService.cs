using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using MassTransit;

using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;
using NodaTime;
using NodaTime.Extensions;
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace treehammock.Services;
public interface IAccountService
{
    Task<HttpMessage> SetupUserAccount(string emailAddress, string? username, string password, Country country, Instant createdOn, AccountSetupAction whichAction);
    Task<HttpMessage> ResendAccountVerification(string emailAddress);
    Task<AccountAdjustResult?> RequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress);
    Task<AccountAdjustResult?> CompleteEmailChange(string verifyKey);
    Task<AccountDeleteCommandResult?> RequestAccountDelete(Guid accountId, Guid accountSecurityStamp, string? passPhrase);
    Task<AccountDeleteCommandResult?> VerifyAccountDeleteToken(string deleteToken);
    Task<AccountDeleteCommandResult?> FinalizeAccountDelete(Guid accountId, Guid accountSecurityStamp, string deleteToken, string? passPhrase);
    Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant? moment = null);
    Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant? moment = null);
}

public class AccountService : IAccountService
{
    private IAccountRepo _accountRepo { get; set; }
    private ISMTPService _smtpService { get; set; }
    private LoginSettings _loginSettings { get; set; }
    private RegistrationSettings _registrationSettings { get; set; }
    private EmailSubjectSettings _emailSubjectSettings { get; set; }
    private IUserSecretHasher _userSecretHasher { get; set; }
    private IDeliveryAbuseThrottleService _deliveryAbuseThrottleService { get; set; }
    private IAccountTokenVerificationAbuseCounterKeyFactory _accountTokenVerificationAbuseCounterKeyFactory { get; set; }
    private IAbuseCounterStore? _abuseCounterStore { get; set; }
    private AbuseControlSettings _abuseControlSettings { get; set; }
    private IHttpContextAccessor? _httpContextAccessor { get; set; }

    private const int WebKeyPos = 0;
    private const int SaltPos = WebKeyPos + AccountCryptoSizes.WebKeyBytes;
    private const int SivPos = SaltPos + AccountCryptoSizes.SaltOneBytes;
    private const int NoncePos = SivPos + AccountCryptoSizes.SivBytes;
    private const int AccountSecretBytes = AccountCryptoSizes.WebKeyBytes + AccountCryptoSizes.SaltOneBytes + AccountCryptoSizes.SivBytes + AccountCryptoSizes.NonceBytes;

    public AccountService(
        IAccountRepo accountRepo,
        ISMTPService smtpService,
        IOptions<LoginSettings> loginSettings,
        IOptions<RegistrationSettings> registrationSettings,
        IOptions<EmailSubjectSettings> emailSubjectSettings,
        IUserSecretHasher userSecretHasher,
        IDeliveryAbuseThrottleService? deliveryAbuseThrottleService = null,
        IAccountTokenVerificationAbuseCounterKeyFactory? accountTokenVerificationAbuseCounterKeyFactory = null,
        IAbuseCounterStore? abuseCounterStore = null,
        IOptions<AbuseControlSettings>? abuseControlSettings = null,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _accountRepo = accountRepo;
        _smtpService = smtpService;
        _loginSettings = loginSettings.Value;
        _registrationSettings = registrationSettings.Value;
        _emailSubjectSettings = emailSubjectSettings.Value;
        _userSecretHasher = userSecretHasher;
        _deliveryAbuseThrottleService = deliveryAbuseThrottleService ?? NullDeliveryAbuseThrottleService.Instance;
        _accountTokenVerificationAbuseCounterKeyFactory = accountTokenVerificationAbuseCounterKeyFactory ?? new AccountTokenVerificationAbuseCounterKeyFactory();
        _abuseCounterStore = abuseCounterStore;
        _abuseControlSettings = abuseControlSettings?.Value ?? new AbuseControlSettings();
        _httpContextAccessor = httpContextAccessor;
    }

    public byte[] GetPortion(byte[] whole, int length, int offset = 0)
    {
        byte[] result = new byte[length];
        for (int idx = 0; idx < length; idx++)
        {
            result[idx] = whole[idx + offset];
        }
        return result;
    }


    /*
     * Returns one of: 
     *      HttpMessage.ACCOUNT_CREATION_SUCCESSED
     *      HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME
     *      HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL
     *      HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL
     *      HttpMessage.ACCOUNT_CREATION_FAILED
     */
    public async Task<HttpMessage> SetupUserAccount(string emailAddress, string? username, string password, Country country, Instant createdOn, AccountSetupAction whichAction)
    {
        byte[] passwordHash = Argon2idPasswordHashCodec.HashToStorageBytes(password, _loginSettings.Argon2Iterations, _loginSettings.Argon2MemoryUsePer);

        long? verificationIndex = null;
        HttpMessage outcome = HttpMessage.ACCOUNT_CREATION_FAILED;
        string? verifyKey = null;
        Guid accountGuid = Guid.Empty;
        int guidAttempts = 0;
        int webKeyAttempts = 0;

        while (guidAttempts < _registrationSettings.AccountMetaDataRetries && webKeyAttempts < _registrationSettings.AccountMetaDataRetries)
        {
            byte[] transit = RandomNumberGenerator.GetBytes(AccountSecretBytes);
            byte[] webKeyBytes = GetPortion(transit, AccountCryptoSizes.WebKeyBytes, WebKeyPos);
            accountGuid = NewId.NextGuid();
            string webKey = AccountVerificationTokenUtility.EncodeBase64Url(webKeyBytes);
            verifyKey = AccountVerificationTokenUtility.GenerateToken();
            string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);

            Period verificationExpiration = BuildVerificationPeriod();

            var newUser = new Account(
                accountGuid,
                emailAddress,
                username,
                passwordHash,
                createdOn,
                webKey,
                VerificationStatus.STARTED,
                GetPortion(transit, AccountCryptoSizes.SaltOneBytes, SaltPos),
                GetPortion(transit, AccountCryptoSizes.SivBytes, SivPos),
                GetPortion(transit, AccountCryptoSizes.NonceBytes, NoncePos),
                null,
                0,
                null,
                country,
                null,
                null);

            (verificationIndex, outcome, _) = await _accountRepo.SetupAccount(newUser, verifyKeyHash, verificationExpiration, whichAction);

            if (outcome == HttpMessage.ACCOUNT_CREATION_SUCCESSED)
            {
                break;
            }

            if (outcome == HttpMessage.DUPLICATE_USER_GUID)
            {
                guidAttempts++;
                continue;
            }

            if (outcome == HttpMessage.DUPLICATE_USER_WEBKEY)
            {
                webKeyAttempts++;
                continue;
            }

            if (outcome == HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL ||
                outcome == HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL ||
                outcome == HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME)
            {
                return outcome;
            }

            return HttpMessage.ACCOUNT_CREATION_FAILED;
        }

        if (outcome != HttpMessage.ACCOUNT_CREATION_SUCCESSED || verificationIndex == null || string.IsNullOrWhiteSpace(verifyKey))
        {
            return HttpMessage.ACCOUNT_CREATION_FAILED;
        }

        bool? verificationStarted = await _accountRepo.StartAccountVerification(accountGuid, verificationIndex);
        if (verificationStarted != true)
        {
            return HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED;
        }

        string verificationUrl = BuildVerificationUrl(verifyKey);
        bool? emailSent = await TrySendEmailWithDeliveryThrottle(
            AbuseFeature.Activation,
            accountGuid,
            emailAddress,
            () => _smtpService.VerificationLetter(emailAddress, _emailSubjectSettings.AccountVerify, verificationUrl));

        if (emailSent != true)
        {
            return HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING;
        }

        return HttpMessage.ACCOUNT_CREATION_SUCCESSED;
    }

    public async Task<HttpMessage> ResendAccountVerification(string emailAddress)
    {
        if (string.IsNullOrWhiteSpace(emailAddress))
        {
            return HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED;
        }

        string verifyKey = AccountVerificationTokenUtility.GenerateToken();
        string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);
        Period verificationExpiration = BuildVerificationPeriod();

        AccountVerificationResendResult? resend = await _accountRepo.ResendAccountVerification(emailAddress, verifyKeyHash, verificationExpiration);
        if (resend?.Result != true)
        {
            return HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED;
        }

        if (string.IsNullOrWhiteSpace(resend.EmailAddress))
        {
            return HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT;
        }

        string verificationUrl = BuildVerificationUrl(verifyKey);
        bool? emailSent = await TrySendEmailWithDeliveryThrottle(
            AbuseFeature.Activation,
            null,
            resend.EmailAddress,
            () => _smtpService.ResendVerifyLetter(resend.EmailAddress, _emailSubjectSettings.AccountVerifyResend, verificationUrl));

        return emailSent == true
            ? HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT
            : HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING;
    }

    public async Task<AccountAdjustResult?> RequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress)
    {
        AccountSecurityStampGuard.Require(accountSecurityStamp);

        string verifyKey = AccountVerificationTokenUtility.GenerateToken();
        string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);
        Instant expiration = SystemClock.Instance.GetCurrentInstant().Plus(BuildEmailChangeVerificationPeriod().ToDuration());

        AccountAdjustResult? request = await _accountRepo.RequestEmailChange(
            accountId,
            accountSecurityStamp,
            newEmailAddress,
            verifyKeyHash,
            expiration);

        if (request?.Result != true || string.IsNullOrWhiteSpace(request.EmailAddress))
        {
            return request;
        }

        string verificationUrl = BuildEmailChangeVerificationUrl(verifyKey);
        bool? emailSent = await TrySendEmailWithDeliveryThrottle(
            AbuseFeature.Delivery,
            accountId,
            request.EmailAddress,
            () => _smtpService.EmailChangeVerifyLetter(
                request.EmailAddress,
                _emailSubjectSettings.AccountEmailChangeVerify,
                verificationUrl));

        if (emailSent == true)
        {
            return new AccountAdjustResult(
                true,
                HttpMessage.ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING.ToString(),
                request.AccountSecurityStamp,
                request.EmailAddress);
        }

        AccountAdjustResult? cancelled = await _accountRepo.CancelEmailChangeRequest(
            accountId,
            accountSecurityStamp,
            verifyKeyHash);

        if (cancelled?.Result == true)
        {
            return new AccountAdjustResult(
                false,
                HttpMessage.ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED.ToString(),
                request.AccountSecurityStamp,
                request.EmailAddress);
        }

        return new AccountAdjustResult(
            false,
            HttpMessage.ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED.ToString(),
            request.AccountSecurityStamp,
            request.EmailAddress);
    }

    public async Task<AccountAdjustResult?> CompleteEmailChange(string verifyKey)
    {
        verifyKey = verifyKey?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(verifyKey) ||
            verifyKey.Length > AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength)
        {
            return new AccountAdjustResult(false, HttpMessage.ACCOUNT_ADJUST_TOKEN_MISMATCH.ToString());
        }

        AbuseDecision abuseDecision = await CheckPublicTokenVerificationPolicy("email-change", verifyKey);
        if (!abuseDecision.Allowed)
        {
            return new AccountAdjustResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        }

        string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);
        AccountAdjustResult? result = await _accountRepo.CompleteEmailChange(verifyKeyHash);
        if (result?.Result == true)
        {
            await ResetPublicTokenVerificationPolicy("email-change", verifyKey);
        }

        return result;
    }

    public async Task<AccountDeleteCommandResult?> RequestAccountDelete(Guid accountId, Guid accountSecurityStamp, string? passPhrase)
    {
        AccountSecurityStampGuard.Require(accountSecurityStamp);

        string deleteToken = AccountVerificationTokenUtility.GenerateToken();
        string deleteTokenHash = SecretHashUtility.HashLookupToken(deleteToken);
        string? passPhraseHash = string.IsNullOrWhiteSpace(passPhrase)
            ? null
            : _userSecretHasher.HashUserSecret(passPhrase);
        Instant expiration = SystemClock.Instance.GetCurrentInstant().Plus(BuildAccountDeleteTokenPeriod().ToDuration());

        AccountDeleteCommandResult? request = await _accountRepo.RequestAccountDelete(
            accountId,
            accountSecurityStamp,
            passPhraseHash,
            deleteTokenHash,
            expiration,
            BuildDeleteRequestCooldownPeriod(),
            BuildDeleteRequestWindowPeriod(),
            _registrationSettings.DeleteMaxRequestsPerWindow);

        if (request?.Result != true || string.IsNullOrWhiteSpace(request.EmailAddress))
        {
            return request;
        }

        string verificationUrl = BuildAccountDeleteVerificationUrl(deleteToken);
        bool? emailSent = await TrySendEmailWithDeliveryThrottle(
            AbuseFeature.Delivery,
            accountId,
            request.EmailAddress,
            () => _smtpService.DeleteAccountTwoStepLetter(
                request.EmailAddress,
                _emailSubjectSettings.AccountDeleteVerify,
                verificationUrl,
                deleteToken));

        if (emailSent == true)
        {
            return new AccountDeleteCommandResult(
                true,
                HttpMessage.ACCOUNT_DELETE_PENDING.ToString(),
                request.Workflow,
                request.EmailAddress,
                request.AccountId);
        }

        AccountDeleteCommandResult? cancelled = await _accountRepo.CancelAccountDeleteRequest(
            accountId,
            accountSecurityStamp,
            deleteTokenHash);

        if (cancelled?.Result == true)
        {
            return new AccountDeleteCommandResult(
                false,
                HttpMessage.ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED.ToString(),
                request.Workflow,
                request.EmailAddress,
                request.AccountId);
        }

        return new AccountDeleteCommandResult(
            false,
            HttpMessage.ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED.ToString(),
            request.Workflow,
            request.EmailAddress,
            request.AccountId);
    }

    public async Task<AccountDeleteCommandResult?> VerifyAccountDeleteToken(string deleteToken)
    {
        deleteToken = deleteToken?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(deleteToken))
        {
            return new AccountDeleteCommandResult(false, HttpMessage.ACCOUNT_DELETE_TOKEN_MISMATCH.ToString());
        }

        AbuseDecision abuseDecision = await CheckPublicTokenVerificationPolicy("account-delete", deleteToken);
        if (!abuseDecision.Allowed)
        {
            return new AccountDeleteCommandResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        }

        string deleteTokenHash = SecretHashUtility.HashLookupToken(deleteToken);
        AccountDeleteCommandResult? result = await _accountRepo.VerifyDeleteAccountToken(deleteTokenHash);
        if (result?.Result == true)
        {
            await ResetPublicTokenVerificationPolicy("account-delete", deleteToken);
        }

        return result;
    }

    public async Task<AccountDeleteCommandResult?> FinalizeAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteToken,
        string? passPhrase)
    {
        AccountSecurityStampGuard.Require(accountSecurityStamp);

        deleteToken = deleteToken?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(deleteToken))
        {
            return new AccountDeleteCommandResult(false, HttpMessage.ACCOUNT_DELETE_TOKEN_MISMATCH.ToString());
        }

        AbuseDecision abuseDecision = await CheckAccountDeleteFinalizePolicy(accountId, deleteToken);
        if (!abuseDecision.Allowed)
        {
            return new AccountDeleteCommandResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
        }

        string deleteTokenHash = SecretHashUtility.HashLookupToken(deleteToken);

        AccountDeleteCommandResult? result = await _accountRepo.FinalizeAccountDelete(
            accountId,
            accountSecurityStamp,
            deleteTokenHash,
            passPhrase,
            _registrationSettings.DeleteMaxFinalizeFailures,
            BuildDeleteFinalizeLockoutPeriod());

        if (result?.Result == true)
        {
            await ResetAccountDeleteFinalizePolicy(accountId, deleteToken);
        }

        return result;
    }

    public async Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant? moment = null)
    {
        return await _accountRepo.PurgeExpiredDeleteStandby(moment ?? SystemClock.Instance.GetCurrentInstant());
    }

    public async Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant? moment = null)
    {
        return await _accountRepo.PurgeExpiredAccountEmailChangeRequests(moment ?? SystemClock.Instance.GetCurrentInstant());
    }




    private async Task<AbuseDecision> CheckPublicTokenVerificationPolicy(string flow, string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.PublicTokenVerification.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.PublicTokenVerification.VerifyAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.PublicTokenVerification.CooldownSecondsAfterExhaustion);
        var tokenLimit = new AbuseCounterLimit(
            _abuseControlSettings.PublicTokenVerification.MaxVerifyAttemptsPerToken,
            window,
            cooldown);
        var ipLimit = new AbuseCounterLimit(
            _abuseControlSettings.PublicTokenVerification.MaxVerifyAttemptsPerIp,
            window,
            cooldown);

        AbuseDecision tokenDecision = await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForPublicToken(flow, token),
            tokenLimit,
            AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
        if (!tokenDecision.Allowed)
        {
            return tokenDecision;
        }

        return await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForPublicIpAddress(flow, ResolveClientIpAddress()),
            ipLimit,
            AbuseReasonCodes.PublicTokenVerificationAttemptsExceeded);
    }

    private async Task ResetPublicTokenVerificationPolicy(string flow, string token)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.PublicTokenVerification.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForPublicToken(flow, token));
        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForPublicIpAddress(flow, ResolveClientIpAddress()));
    }

    private async Task<AbuseDecision> CheckAccountDeleteFinalizePolicy(Guid accountId, string deleteToken)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountDelete.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.AccountDelete.FinalizeAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.AccountDelete.CooldownSecondsAfterExhaustion);
        var accountLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountDelete.MaxFinalizeAttemptsPerAccount,
            window,
            cooldown);
        var tokenLimit = new AbuseCounterLimit(
            _abuseControlSettings.AccountDelete.MaxFinalizeAttemptsPerToken,
            window,
            cooldown);

        AbuseDecision accountDecision = await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeAccount(accountId),
            accountLimit,
            AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
        if (!accountDecision.Allowed)
        {
            return accountDecision;
        }

        return await IncrementAbuseCounter(
            _accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeToken(deleteToken),
            tokenLimit,
            AbuseReasonCodes.AccountDeleteFinalizeAttemptsExceeded);
    }

    private async Task ResetAccountDeleteFinalizePolicy(Guid accountId, string deleteToken)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.AccountDelete.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeAccount(accountId));
        await _abuseCounterStore.ResetAsync(_accountTokenVerificationAbuseCounterKeyFactory.ForAccountDeleteFinalizeToken(deleteToken));
    }

    private async Task<AbuseDecision> IncrementAbuseCounter(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        string throttleReasonCode)
    {
        CounterDecision decision = await _abuseCounterStore!.IncrementAsync(key, limit);
        if (decision.Allowed)
        {
            return AbuseDecision.Allow();
        }

        string reasonCode = decision.ReasonCode == AbuseReasonCodes.CounterStoreUnavailable || decision.ReasonCode == AbuseReasonCodes.CounterStoreTimeout
            ? decision.ReasonCode!
            : throttleReasonCode;
        AbuseOperationalTelemetry.RecordPolicyDenied(key.Feature, key.Dimension, reasonCode);

        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);
    }

    private string ResolveClientIpAddress()
    {
        IPAddress? remoteIp = _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress;
        return remoteIp?.ToString() ?? "unknown";
    }


    private async Task<bool?> TrySendEmailWithDeliveryThrottle(
        AbuseFeature feature,
        Guid? accountId,
        string emailAddress,
        Func<Task<bool?>> send)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(feature, "email", accountId, DeliveryAbuseThrottleService.SafeDestination("email", emailAddress));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            bool? sent = await send();
            if (sent != true)
            {
                await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            }

            return sent;
        }
        catch
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            return false;
        }
    }

    private Period BuildVerificationPeriod()
    {
        return new PeriodBuilder
        {
            Weeks = _registrationSettings.VerifyAccountPeriodWeeks,
            Days = _registrationSettings.VerifyAccountPeriodDays,
            Hours = _registrationSettings.VerifyAccountPeriodHours
        }.Build();
    }

    private Period BuildEmailChangeVerificationPeriod()
    {
        if (_registrationSettings.EmailChangeVerifyPeriodWeeks == 0 &&
            _registrationSettings.EmailChangeVerifyPeriodDays == 0 &&
            _registrationSettings.EmailChangeVerifyPeriodHours == 0)
        {
            return BuildVerificationPeriod();
        }

        return new PeriodBuilder
        {
            Weeks = _registrationSettings.EmailChangeVerifyPeriodWeeks,
            Days = _registrationSettings.EmailChangeVerifyPeriodDays,
            Hours = _registrationSettings.EmailChangeVerifyPeriodHours
        }.Build();
    }

    private Period BuildAccountDeleteTokenPeriod()
    {
        if (_registrationSettings.AccountDeleteTokenPeriodWeeks == 0 &&
            _registrationSettings.AccountDeleteTokenPeriodDays == 0 &&
            _registrationSettings.AccountDeleteTokenPeriodHours == 0)
        {
            return BuildVerificationPeriod();
        }

        return new PeriodBuilder
        {
            Weeks = _registrationSettings.AccountDeleteTokenPeriodWeeks,
            Days = _registrationSettings.AccountDeleteTokenPeriodDays,
            Hours = _registrationSettings.AccountDeleteTokenPeriodHours
        }.Build();
    }

    private Period BuildDeleteRequestCooldownPeriod()
    {
        return Period.FromMinutes(_registrationSettings.DeleteRequestCooldownMinutes);
    }

    private Period BuildDeleteRequestWindowPeriod()
    {
        return Period.FromHours(_registrationSettings.DeleteRequestWindowHours);
    }

    private Period BuildDeleteFinalizeLockoutPeriod()
    {
        return Period.FromMinutes(_registrationSettings.DeleteFinalizeLockoutMinutes);
    }


    private string BuildVerificationUrl(string verifyKey)
    {
        string encodedPayload = WebUtility.UrlEncode(verifyKey);
        string relativePath = $"/account/verifyaccount?payload={encodedPayload}";
        return BuildUrl(_registrationSettings.AccountVerificationBaseUrl, relativePath);
    }

    private string BuildEmailChangeVerificationUrl(string verifyKey)
    {
        string encodedPayload = WebUtility.UrlEncode(verifyKey);
        string relativePath = $"/account/adjust/email/verify?payload={encodedPayload}";
        string? baseUrl = string.IsNullOrWhiteSpace(_registrationSettings.AccountEmailChangeVerificationBaseUrl)
            ? _registrationSettings.AccountVerificationBaseUrl
            : _registrationSettings.AccountEmailChangeVerificationBaseUrl;

        return BuildUrl(baseUrl, relativePath);
    }

    private string BuildAccountDeleteVerificationUrl(string deleteToken)
    {
        string encodedPayload = WebUtility.UrlEncode(deleteToken);
        string relativePath = $"/account/wipeout/verify?payload={encodedPayload}";
        string? baseUrl = string.IsNullOrWhiteSpace(_registrationSettings.AccountDeleteVerifyBaseUrl)
            ? _registrationSettings.AccountVerificationBaseUrl
            : _registrationSettings.AccountDeleteVerifyBaseUrl;

        return BuildUrl(baseUrl, relativePath);
    }


    private static string BuildUrl(string? baseUrl, string relativePath)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            return relativePath;
        }

        return $"{baseUrl.TrimEnd('/')}{relativePath}";
    }


}
