using System.Net;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.DataLayer;
using treehammock.Models.Activation;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Services;

public sealed record ActivationCreateResult(bool Result, string Code);
public sealed record ActivationDisableResult(bool Result, string Code);
public sealed record ActivationVerifyResult(bool Result, string Code, ActivationQuery? Activation);

public interface IActivationService
{
    Task<ActivationCreateResult> PlaceActivation(Guid accountId, Guid accountSecurityStamp, ActivationCreationRequest request, Instant createdOn);
    Task<ActivationDisableResult> DisableActivation(Guid accountId, Guid accountSecurityStamp, ActivationUnSubscribeRequest request, Instant moment);
    Task<ActivationVerifyResult> VerifyActivation(Guid accountId, Guid accountSecurityStamp, ActivationDetailsRequest request, Instant moment);
}

public class ActivationService : IActivationService
{
    public const string CreatedCode = "ACTIVATION_CREATED";
    public const string VerifiedCode = "ACTIVATION_VERIFIED";
    public const string DisabledCode = "ACTIVATION_DISABLED";
    public const string FailedCode = "ACTIVATION_FAILED";
    public const string NotFoundCode = "ACTIVATION_NOT_FOUND";
    public const string SecurityStampMismatchCode = "ACCOUNT_SECURITY_STAMP_MISMATCH";
    public const string EmailMismatchCode = "ACTIVATION_EMAIL_MISMATCH";
    public const string ExpiredCode = "ACTIVATION_EXPIRED";
    public const string CodeMismatchCode = "ACTIVATION_CODE_MISMATCH";
    public const string InvalidCode = "ACTIVATION_INVALID";
    public const string InvalidTermCode = "ACTIVATION_INVALID_TERM";
    public const string InvalidRecycleCode = "ACTIVATION_INVALID_RECYCLE";
    public const string ConflictCode = "ACTIVATION_CONFLICT";
    public const string StoredCode = "ACTIVATION_STORED";
    public const string EmailDeliveryFailedCode = "ACTIVATION_EMAIL_DELIVERY_FAILED";
    public const string CleanupFailedCode = "ACTIVATION_CLEANUP_FAILED";

    private const string ActivationPlatformText = "backend";
    private const int ActivationCodeByteLength = 18;

    private readonly IActivationRepo _activationRepo;
    private readonly ISMTPService _smtpService;
    private readonly EmailSubjectSettings _emailSubjectSettings;
    private readonly ILogger<ActivationService> _logger;
    private readonly IDeliveryAbuseThrottleService _deliveryAbuseThrottleService;
    private readonly IActivationAbuseCounterKeyFactory _activationAbuseCounterKeyFactory;
    private readonly IAbuseCounterStore? _abuseCounterStore;
    private readonly AbuseControlSettings _abuseControlSettings;
    private readonly IHttpContextAccessor? _httpContextAccessor;

    public ActivationService(
        IActivationRepo activationRepo,
        ISMTPService smtpService,
        IOptions<EmailSubjectSettings>? emailSubjectSettings,
        ILogger<ActivationService> logger,
        IDeliveryAbuseThrottleService? deliveryAbuseThrottleService = null,
        IActivationAbuseCounterKeyFactory? activationAbuseCounterKeyFactory = null,
        IAbuseCounterStore? abuseCounterStore = null,
        IOptions<AbuseControlSettings>? abuseControlSettings = null,
        IHttpContextAccessor? httpContextAccessor = null)
    {
        _activationRepo = activationRepo;
        _smtpService = smtpService;
        _emailSubjectSettings = emailSubjectSettings?.Value ?? new EmailSubjectSettings();
        _logger = logger;
        _deliveryAbuseThrottleService = deliveryAbuseThrottleService ?? NullDeliveryAbuseThrottleService.Instance;
        _activationAbuseCounterKeyFactory = activationAbuseCounterKeyFactory ?? new ActivationAbuseCounterKeyFactory();
        _abuseCounterStore = abuseCounterStore;
        _abuseControlSettings = abuseControlSettings?.Value ?? new AbuseControlSettings();
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<ActivationCreateResult> PlaceActivation(Guid accountId, Guid accountSecurityStamp, ActivationCreationRequest request, Instant createdOn)
    {
        if (!Enum.IsDefined(typeof(FeatureSet), (int)request.featureSet))
        {
            return new ActivationCreateResult(false, FailedCode);
        }

        if (!IsSupportedActivationTerm(request.term))
        {
            return new ActivationCreateResult(false, InvalidTermCode);
        }

        if (!IsSupportedActivationRecycle(request.recycle))
        {
            return new ActivationCreateResult(false, InvalidRecycleCode);
        }

        FeatureSet featureSet = (FeatureSet)request.featureSet;

        string activationCode = GenerateActivationCode();
        Instant closeOff = ResolveCloseOff(createdOn, request.term);

        ActivationCommandResult? placed = await _activationRepo.PlaceActivation(
            accountId,
            accountSecurityStamp,
            NormalizeEmail(request.emailAddress),
            activationCode,
            createdOn,
            request.term,
            request.recycle,
            closeOff,
            featureSet,
            PlatformBacker.Intra,
            ActivationPlatformText,
            ActivationStatus.PENDING,
            delayedStart: null);

        if (placed is null)
        {
            return new ActivationCreateResult(false, FailedCode);
        }

        if (!placed.Result || placed.Status != ActivationStatus.PENDING)
        {
            return new ActivationCreateResult(false, NormalizeRepositoryCode(placed.Code));
        }

        bool delivered = await TrySendActivationCode(accountId, request.emailAddress, activationCode);
        if (delivered)
        {
            return new ActivationCreateResult(true, CreatedCode);
        }

        ActivationCommandResult? cancelled = await _activationRepo.CancelActivationRequest(
            accountId,
            accountSecurityStamp,
            activationCode,
            createdOn);

        return cancelled?.Result == true && cancelled.Status == ActivationStatus.DISRUPTED
            ? new ActivationCreateResult(false, EmailDeliveryFailedCode)
            : new ActivationCreateResult(false, CleanupFailedCode);
    }

    public async Task<ActivationDisableResult> DisableActivation(Guid accountId, Guid accountSecurityStamp, ActivationUnSubscribeRequest request, Instant moment)
    {
        ActivationCommandResult? disabled = await _activationRepo.DisableActivation(
            accountId,
            accountSecurityStamp,
            NormalizeEmail(request.emailAddress),
            moment,
            moment,
            ActivationStatus.DISRUPTED);

        if (disabled is null)
        {
            return new ActivationDisableResult(false, FailedCode);
        }

        return disabled.Result && disabled.Status == ActivationStatus.DISRUPTED
            ? new ActivationDisableResult(true, DisabledCode)
            : new ActivationDisableResult(false, NormalizeRepositoryCode(disabled.Code));
    }

    public async Task<ActivationVerifyResult> VerifyActivation(Guid accountId, Guid accountSecurityStamp, ActivationDetailsRequest request, Instant moment)
    {
        string normalizedEmail = NormalizeEmail(request.emailAddress);
        AbuseDecision abuseDecision = await CheckActivationVerifyAttemptPolicy(accountId, normalizedEmail);
        if (!abuseDecision.Allowed)
        {
            return new ActivationVerifyResult(false, abuseDecision.ReasonCode ?? AbuseReasonCodes.ActivationVerifyAttemptsExceeded, null);
        }

        ActivationVerifyCommandResult? verification = await _activationRepo.VerifyActivation(
            accountId,
            accountSecurityStamp,
            normalizedEmail,
            request.code.Trim(),
            moment,
            position: 0,
            upperLimit: 1);

        if (verification is null)
        {
            return new ActivationVerifyResult(false, FailedCode, null);
        }

        if (verification.Result && verification.Activation is not null)
        {
            await ResetActivationVerifyAttemptPolicy(accountId, normalizedEmail);
            return new ActivationVerifyResult(true, VerifiedCode, verification.Activation);
        }

        return new ActivationVerifyResult(false, NormalizeRepositoryCode(verification.Code), null);
    }

    private async Task<AbuseDecision> CheckActivationVerifyAttemptPolicy(Guid accountId, string normalizedEmail)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.Activation.Enabled
            || _abuseCounterStore is null)
        {
            return AbuseDecision.Allow();
        }

        TimeSpan window = TimeSpan.FromSeconds(_abuseControlSettings.Activation.VerifyAttemptWindowSeconds);
        TimeSpan cooldown = TimeSpan.FromSeconds(_abuseControlSettings.Activation.CooldownSecondsAfterExhaustion);
        var accountLimit = new AbuseCounterLimit(
            _abuseControlSettings.Activation.MaxVerifyAttemptsPerAccount,
            window,
            cooldown);
        var identifierLimit = new AbuseCounterLimit(
            _abuseControlSettings.Activation.MaxVerifyAttemptsPerIdentifier,
            window,
            cooldown);
        var ipLimit = new AbuseCounterLimit(
            _abuseControlSettings.Activation.MaxVerifyAttemptsPerIp,
            window,
            cooldown);

        AbuseDecision accountDecision = await IncrementActivationVerifyCounter(
            _activationAbuseCounterKeyFactory.ForVerifyAccount(accountId),
            accountLimit);
        if (!accountDecision.Allowed)
        {
            return accountDecision;
        }

        AbuseDecision identifierDecision = await IncrementActivationVerifyCounter(
            _activationAbuseCounterKeyFactory.ForVerifyIdentifier(normalizedEmail),
            identifierLimit);
        if (!identifierDecision.Allowed)
        {
            return identifierDecision;
        }

        return await IncrementActivationVerifyCounter(
            _activationAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()),
            ipLimit);
    }

    private async Task<AbuseDecision> IncrementActivationVerifyCounter(
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
            : AbuseReasonCodes.ActivationVerifyAttemptsExceeded;
        AbuseOperationalTelemetry.RecordPolicyDenied(key.Feature, key.Dimension, reasonCode);

        return AbuseDecision.Deny(reasonCode, decision.RetryAfter);
    }

    private async Task ResetActivationVerifyAttemptPolicy(Guid accountId, string normalizedEmail)
    {
        if (!_abuseControlSettings.Enabled
            || !_abuseControlSettings.Activation.Enabled
            || _abuseCounterStore is null)
        {
            return;
        }

        await _abuseCounterStore.ResetAsync(_activationAbuseCounterKeyFactory.ForVerifyAccount(accountId));
        await _abuseCounterStore.ResetAsync(_activationAbuseCounterKeyFactory.ForVerifyIdentifier(normalizedEmail));
        await _abuseCounterStore.ResetAsync(_activationAbuseCounterKeyFactory.ForVerifyIpAddress(ResolveClientIpAddress()));
    }

    private string ResolveClientIpAddress()
    {
        IPAddress? remoteIp = _httpContextAccessor?.HttpContext?.Connection.RemoteIpAddress;
        return remoteIp?.ToString() ?? "unknown";
    }

    internal static string GenerateActivationCode()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(ActivationCodeByteLength);
        string code = Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        return code;
    }

    internal static Instant ResolveCloseOff(Instant createdOn, DayDuration term)
    {
        return term switch
        {
            DayDuration.DAILY => createdOn.Plus(Duration.FromDays(1)),
            DayDuration.WEEKLY => createdOn.Plus(Duration.FromDays(7)),
            DayDuration.BIWEEKLY => createdOn.Plus(Duration.FromDays(14)),
            DayDuration.MONTHFIRST or DayDuration.MONTHLAST or DayDuration.MONTHLY => createdOn.Plus(Duration.FromDays(31)),
            DayDuration.QUARTERYEAR => createdOn.Plus(Duration.FromDays(91)),
            DayDuration.SEMIYEAR => createdOn.Plus(Duration.FromDays(182)),
            DayDuration.TRIQUARTERYEAR => createdOn.Plus(Duration.FromDays(273)),
            DayDuration.YEAR => createdOn.Plus(Duration.FromDays(365)),
            DayDuration.INDEFINITE => createdOn.Plus(Duration.FromDays(36500)),
            _ => throw new ArgumentOutOfRangeException(nameof(term), term, "Unsupported activation term.")
        };
    }

    internal static bool IsSupportedActivationTerm(DayDuration term)
    {
        return Enum.IsDefined(typeof(DayDuration), term);
    }

    internal static bool IsSupportedActivationRecycle(DurationRepeat recycle)
    {
        return Enum.IsDefined(typeof(DurationRepeat), recycle);
    }

    private async Task<bool> TrySendActivationCode(Guid accountId, string emailAddress, string activationCode)
    {
        var throttleRequest = new DeliveryAbuseThrottleRequest(AbuseFeature.Activation, "email", accountId, DeliveryAbuseThrottleService.SafeDestination("email", emailAddress));
        AbuseDecision throttle = await _deliveryAbuseThrottleService.ShouldAllowDeliveryAsync(throttleRequest);
        if (!throttle.Allowed)
        {
            return false;
        }

        try
        {
            string body = BuildActivationEmailBody(activationCode);
            bool? sent = await _smtpService.Send(emailAddress, _emailSubjectSettings.ActivationCode, body);
            if (sent != true)
            {
                await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            }

            return sent == true;
        }
        catch (Exception ex)
        {
            await _deliveryAbuseThrottleService.RecordProviderFailureAsync(throttleRequest);
            _logger.LogWarning(ex, "Activation code delivery failed for {RecipientDomain}.", RecipientDomain(emailAddress));
            return false;
        }
    }

    private static string BuildActivationEmailBody(string activationCode)
    {
        return new StringBuilder()
            .Append("<p>Your Treehammock activation code is:</p>")
            .Append("<p><strong>")
            .Append(activationCode)
            .Append("</strong></p>")
            .ToString();
    }

    private static string NormalizeRepositoryCode(string? code)
    {
        return code switch
        {
            NotFoundCode => NotFoundCode,
            SecurityStampMismatchCode => SecurityStampMismatchCode,
            EmailMismatchCode => EmailMismatchCode,
            ExpiredCode => ExpiredCode,
            CodeMismatchCode => CodeMismatchCode,
            InvalidCode => InvalidCode,
            InvalidTermCode => InvalidTermCode,
            InvalidRecycleCode => InvalidRecycleCode,
            ConflictCode => ConflictCode,
            StoredCode => StoredCode,
            AbuseReasonCodes.ActivationVerifyAttemptsExceeded => AbuseReasonCodes.ActivationVerifyAttemptsExceeded,
            AbuseReasonCodes.CounterStoreUnavailable => AbuseReasonCodes.CounterStoreUnavailable,
            AbuseReasonCodes.CounterStoreTimeout => AbuseReasonCodes.CounterStoreTimeout,
            _ => FailedCode
        };
    }

    private static string NormalizeEmail(string emailAddress)
    {
        return emailAddress.Trim().ToLowerInvariant();
    }

    private static string RecipientDomain(string emailAddress)
    {
        int atIndex = emailAddress.LastIndexOf('@');
        return atIndex >= 0 && atIndex < emailAddress.Length - 1
            ? emailAddress[(atIndex + 1)..]
            : "unknown";
    }
}
