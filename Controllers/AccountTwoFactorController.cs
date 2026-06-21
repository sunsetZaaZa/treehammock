using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Globalization;

using NodaTime;
using Geralt;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Models.Authentication;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Authorization;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Services;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Entities;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.Models.Api;

namespace treehammock.Controllers;

[Authenticate]
[ApiController]
[Route("account")]
[Produces("application/json")]
public sealed class AccountTwoFactorController : AccountControllerBase
{
    public AccountTwoFactorController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
                                IJsonWebTokenUtility jwtUtility, ITwoFactorAuthenticateService twoFactorService, IAccountService accountService,
                                IAbuseCounterStore abuseCounterStore, ILoginAbuseCounterKeyFactory loginAbuseCounterKeyFactory,
                                IOptions<RegistrationSettings> registrationSettings, IOptions<JWTSettings> jwtSettings, IOptions<LoginSettings> loginSettings,
                                IOptions<AbuseControlSettings> abuseControlSettings,
                                IOptions<EmailTemplateSettings>? emailTemplateSettings = null,
                                IAccountTokenVerificationAbuseCounterKeyFactory? accountTokenVerificationAbuseCounterKeyFactory = null,
                                IAuthenticatedMutationIdempotencyService? authenticatedMutationIdempotencyService = null)
        : base(accountRepo,
        sessionRepo,
        activeUserCacheService,
        twoFactorSessionService,
        jwtUtility,
        twoFactorService,
        accountService,
        abuseCounterStore,
        loginAbuseCounterKeyFactory,
        registrationSettings,
        jwtSettings,
        loginSettings,
        abuseControlSettings,
        emailTemplateSettings,
        accountTokenVerificationAbuseCounterKeyFactory,
        authenticatedMutationIdempotencyService)
    {
    }



    [HttpPost("twofactor/authenticator/setup")]
    [ProducesResponseType(typeof(ApiResponse<StartAuthenticatorAppSetupResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<StartAuthenticatorAppSetupResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<StartAuthenticatorAppSetupResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<StartAuthenticatorAppSetupResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<StartAuthenticatorAppSetupResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<StartAuthenticatorAppSetupResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<StartAuthenticatorAppSetupResponse>>> StartAuthenticatorAppSetup([FromBody] StartAuthenticatorAppSetupRequest? payload)
    {
        var validation = ValidateStartAuthenticatorAppSetupRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(SerializeAuthenticatorSetupStart(false, HttpMessage.AUTHENTICATION_FAILED, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/twofactor/authenticator/setup", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new StartAuthenticatorAppSetupResponse(HttpMessage.AUTHENTICATOR_SETUP_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (statusCode, code) => new StartAuthenticatorAppSetupResponse(AuthenticatorSetupMessage(code), statusCode >= StatusCodes.Status200OK && statusCode < StatusCodes.Status300MultipleChoices)
            {
                supportedAuthenticatorApps = SupportedAuthenticatorApps
            });
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<StartAuthenticatorAppSetupResponse>>> CompleteAndReturn(ApiOutcome<StartAuthenticatorAppSetupResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        IAccountSensitiveActionService? sensitiveActionService = HttpContext.RequestServices.GetService<IAccountSensitiveActionService>();
        if (sensitiveActionService is null)
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupStart(false, HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED, StatusCodes.Status500InternalServerError, AccountSensitiveActionService.TokenValidationFailedCode));
        }

        SensitiveActionValidationResult tokenValidation = await ValidateSensitiveActionToken(
            sensitiveActionService,
            activeSession,
            hashedAccessToken,
            consume: true);
        if (!tokenValidation.Succeeded)
        {
            int statusCode = MissingSensitiveActionToken() ? StatusCodes.Status428PreconditionRequired : StatusCodes.Status401Unauthorized;
            return await CompleteAndReturn(SerializeAuthenticatorSetupStart(false, tokenValidation.Result, statusCode, tokenValidation.Code));
        }

        AccountViewResult? accountView = await SafeViewAccount(activeSession.accountId, activeSession.accountSecurityStamp);
        if (accountView?.Result != true || accountView.Profile is null || string.IsNullOrWhiteSpace(accountView.Profile.emailAddress))
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupStart(false, HttpMessage.AUTHENTICATOR_SETUP_FAILED, StatusCodes.Status500InternalServerError, accountView?.Code ?? AccountViewFailedCode));
        }

        IAuthenticatorAppSetupService? setupService = HttpContext.RequestServices.GetService<IAuthenticatorAppSetupService>();
        if (setupService is null)
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupStart(false, HttpMessage.AUTHENTICATOR_SETUP_FAILED, StatusCodes.Status500InternalServerError, AuthenticatorAppSetupService.SetupStartFailedCode));
        }

        StartAuthenticatorAppSetupResult result = await setupService.StartSetupAsync(
            new StartAuthenticatorAppSetupCommand(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                accountView.Profile.emailAddress,
                payload!.label,
                payload.required,
                payload.provider),
            HttpContext.RequestAborted);

        var body = new StartAuthenticatorAppSetupResponse(AuthenticatorSetupMessage(result.Code), result.Succeeded)
        {
            setupId = result.Succeeded ? result.SetupId : null,
            otpauthUri = result.Succeeded ? result.OtpauthUri : null,
            manualEntryKey = result.Succeeded ? result.ManualEntryKey : null,
            issuer = result.Succeeded ? result.Issuer : null,
            accountName = result.Succeeded ? result.AccountName : null,
            periodSeconds = result.Succeeded ? result.PeriodSeconds : null,
            digits = result.Succeeded ? result.Digits : null,
            hashAlgorithm = result.Succeeded ? result.HashAlgorithm : null,
            provider = result.ProviderType,
            expiration = result.Expiration,
            supportedAuthenticatorApps = SupportedAuthenticatorApps
        };

        int responseStatus = result.Succeeded ? StatusCodes.Status202Accepted : AuthenticatorSetupStatus(result.Code);
        return await CompleteAndReturn(new ApiOutcome<StartAuthenticatorAppSetupResponse>(body, responseStatus, result.Code));
    }

    [HttpPost("twofactor/authenticator/verify")]
    [ProducesResponseType(typeof(ApiResponse<VerifyAuthenticatorAppSetupResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<VerifyAuthenticatorAppSetupResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<VerifyAuthenticatorAppSetupResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<VerifyAuthenticatorAppSetupResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<VerifyAuthenticatorAppSetupResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<VerifyAuthenticatorAppSetupResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<VerifyAuthenticatorAppSetupResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<VerifyAuthenticatorAppSetupResponse>>> VerifyAuthenticatorAppSetup([FromBody] VerifyAuthenticatorAppSetupRequest? payload)
    {
        var validation = ValidateVerifyAuthenticatorAppSetupRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string oldHashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(SerializeAuthenticatorSetupVerify(false, HttpMessage.AUTHENTICATION_FAILED, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/twofactor/authenticator/verify", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new VerifyAuthenticatorAppSetupResponse(HttpMessage.AUTHENTICATOR_SETUP_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (statusCode, code) => new VerifyAuthenticatorAppSetupResponse(AuthenticatorSetupMessage(code), statusCode >= StatusCodes.Status200OK && statusCode < StatusCodes.Status300MultipleChoices));
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<VerifyAuthenticatorAppSetupResponse>>> CompleteAndReturn(ApiOutcome<VerifyAuthenticatorAppSetupResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        string? webKey = HttpContext.Items[AuthContextItems.WebKey] as string;
        if (string.IsNullOrWhiteSpace(webKey))
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupVerify(false, HttpMessage.AUTHENTICATION_FAILED, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        IAuthenticatorAppSetupService? setupService = HttpContext.RequestServices.GetService<IAuthenticatorAppSetupService>();
        if (setupService is null)
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupVerify(false, HttpMessage.AUTHENTICATOR_SETUP_FAILED, StatusCodes.Status500InternalServerError, AuthenticatorAppSetupService.SetupVerifyFailedCode));
        }

        Instant moment = SystemClock.Instance.GetCurrentInstant();
        Period cachePeriod;
        Instant accessExpiration;
        try
        {
            accessExpiration = ResolveAccessExpiration(moment, activeSession.sessionExpiration, activeSession.cutOff, out cachePeriod);
        }
        catch
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupVerify(false, HttpMessage.AUTHENTICATION_EXPIRED, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_EXPIRED.ToString()));
        }

        byte[] refreshToken = RandomNumberGenerator.GetBytes(_jwtSettings.RefreshTokenBytes);
        string accessToken = _jwtUtility.GenerateAccessToken(refreshToken, webKey);
        string? newHashedAccessToken = HashAccessToken(accessToken);
        if (newHashedAccessToken == null)
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupVerify(false, HttpMessage.AUTHENTICATOR_SETUP_FAILED, StatusCodes.Status500InternalServerError, AuthenticatorAppSetupService.SetupVerifyFailedCode));
        }

        Guid sessionSecurityStamp = Guid.NewGuid();
        VerifyAuthenticatorAppSetupAndRotateSessionResult result = await setupService.VerifySetupAndRotateSessionAsync(
            new VerifyAuthenticatorAppSetupAndRotateSessionCommand(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                payload!.setupId,
                payload.totpCode,
                oldHashedAccessToken,
                newHashedAccessToken,
                refreshToken,
                0,
                0,
                moment,
                activeSession.sessionLifespan,
                accessExpiration,
                activeSession.sessionExpiration,
                activeSession.cutOff,
                activeSession.features,
                sessionSecurityStamp),
            HttpContext.RequestAborted);

        if (!result.Succeeded || result.NewAccountSecurityStamp is null)
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupVerify(false, AuthenticatorSetupMessage(result.Code), AuthenticatorSetupStatus(result.Code), result.Code));
        }

        var rotatedSession = new ActiveSession(
            activeSession.accountId,
            refreshToken,
            0,
            moment,
            activeSession.sessionLifespan,
            accessExpiration,
            activeSession.sessionExpiration,
            activeSession.cutOff,
            activeSession.features,
            sessionSecurityStamp,
            result.NewAccountSecurityStamp.Value);

        ActiveCacheWriteResult cached = await SafeSetActiveSession(newHashedAccessToken, rotatedSession, cachePeriod.ToDuration().ToTimeSpan());
        if (!cached.Stored)
        {
            // TOTP-ENROLL-4: the PostgreSQL completion routine is authoritative. It has already
            // promoted the authenticator enrollment, bumped the account security stamp, expired
            // old DB sessions, and inserted the rotated session row. A later middleware fallback
            // can hydrate Dragonfly from PostgreSQL instead of failing open or rolling back a
            // valid account-security mutation after commit.
        }

        ActiveSessionRevokeResult oldCacheRevoked = await SafeRevokeActiveSession(oldHashedAccessToken);
        if (!oldCacheRevoked.Revoked)
        {
            // The old cached session carries the previous account security stamp. If it is seen
            // again, JsonWebTokenMiddleware validates cached trust against PostgreSQL, revokes the
            // stale cache entry, and rejects the request. Cache cleanup is therefore best-effort,
            // while PostgreSQL remains the security source of truth.
        }

        return await CompleteAndReturn(SerializeAuthenticatorSetupVerify(true, HttpMessage.AUTHENTICATOR_SETUP_VERIFIED, StatusCodes.Status200OK, result.Code, accessToken));
    }

    [HttpPost("twofactor/authenticator/cancel")]
    [ProducesResponseType(typeof(ApiResponse<CancelAuthenticatorAppSetupResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<CancelAuthenticatorAppSetupResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<CancelAuthenticatorAppSetupResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<CancelAuthenticatorAppSetupResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<CancelAuthenticatorAppSetupResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<CancelAuthenticatorAppSetupResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<CancelAuthenticatorAppSetupResponse>>> CancelAuthenticatorAppSetup([FromBody] CancelAuthenticatorAppSetupRequest? payload)
    {
        var validation = ValidateCancelAuthenticatorAppSetupRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out _, out ActiveSession activeSession))
        {
            return ToActionResult(SerializeAuthenticatorSetupCancel(false, HttpMessage.AUTHENTICATION_FAILED, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/twofactor/authenticator/cancel", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new CancelAuthenticatorAppSetupResponse(HttpMessage.AUTHENTICATOR_SETUP_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (statusCode, code) => new CancelAuthenticatorAppSetupResponse(AuthenticatorSetupMessage(code), statusCode >= StatusCodes.Status200OK && statusCode < StatusCodes.Status300MultipleChoices));
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<CancelAuthenticatorAppSetupResponse>>> CompleteAndReturn(ApiOutcome<CancelAuthenticatorAppSetupResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        IAuthenticatorAppSetupService? setupService = HttpContext.RequestServices.GetService<IAuthenticatorAppSetupService>();
        if (setupService is null)
        {
            return await CompleteAndReturn(SerializeAuthenticatorSetupCancel(false, HttpMessage.AUTHENTICATOR_SETUP_FAILED, StatusCodes.Status500InternalServerError, AuthenticatorAppSetupService.SetupCancelFailedCode));
        }

        CancelAuthenticatorAppSetupResult result = await setupService.CancelSetupAsync(
            new CancelAuthenticatorAppSetupServiceCommand(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                payload!.setupId),
            HttpContext.RequestAborted);

        return await CompleteAndReturn(SerializeAuthenticatorSetupCancel(
            result.Succeeded,
            result.Succeeded ? HttpMessage.AUTHENTICATOR_SETUP_CANCELLED : AuthenticatorSetupMessage(result.Code),
            result.Succeeded ? StatusCodes.Status200OK : AuthenticatorSetupStatus(result.Code),
            result.Code));
    }

    [HttpPost("setuptwofactormethod")]
    [ProducesResponseType(typeof(ApiResponse<SetupLayeredAuthenticateMethodResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<SetupLayeredAuthenticateMethodResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<SetupLayeredAuthenticateMethodResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<SetupLayeredAuthenticateMethodResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<SetupLayeredAuthenticateMethodResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<SetupLayeredAuthenticateMethodResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<SetupLayeredAuthenticateMethodResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<SetupLayeredAuthenticateMethodResponse>>> SetupTwoFactorMethod([FromBody] SetupLayeredAuthenticateMethodRequest payload)
    {
        var setupValidation = ValidateSetupTwoFactorMethodRequest(payload);
        if (setupValidation != null)
        {
            return ToActionResult(setupValidation);
        }

        if (!TryGetAuthenticatedSession(out _, out ActiveSession activeSession))
        {
            return ToActionResult(SerializeTwoFactorSetup(
                false,
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_EXPIRED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/setuptwofactormethod", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(
            idempotency,
            new SetupLayeredAuthenticateMethodResponse(false));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (statusCode, code) => new SetupLayeredAuthenticateMethodResponse(statusCode >= StatusCodes.Status200OK && statusCode < StatusCodes.Status300MultipleChoices));
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<SetupLayeredAuthenticateMethodResponse>>> CompleteAndReturn(ApiOutcome<SetupLayeredAuthenticateMethodResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        Instant moment = SystemClock.Instance.GetCurrentInstant();
        Period setupPeriod = BuildTwoFactorChallengePeriod();
        Instant expiration = moment.Plus(setupPeriod.ToDuration());
        string codeKey = TwoFactorChallengeCodeUtility.GenerateNumericCode();
        string codeHash = TwoFactorChallengeCodeUtility.Hash(codeKey, _loginSettings.TwoFactorChallengePepper);

        string emailAddress = string.Empty;
        if (payload.method == TwoFactorAuthMethod.EMAIL)
        {
            AccountViewResult? accountView = await SafeViewAccount(activeSession.accountId, activeSession.accountSecurityStamp);
            if (accountView?.Result != true || accountView.Profile is null || string.IsNullOrWhiteSpace(accountView.Profile.emailAddress))
            {
                return await CompleteAndReturn(SerializeTwoFactorSetup(
                    false,
                    StatusCodes.Status500InternalServerError,
                    accountView?.Code ?? AccountViewFailedCode));
            }

            emailAddress = NormalizeTwoFactorEmailContact(accountView.Profile.emailAddress);
            string requestedEmailAddress = NormalizeTwoFactorEmailContact(payload.contact);
            if (!string.Equals(requestedEmailAddress, emailAddress, StringComparison.OrdinalIgnoreCase))
            {
                return await CompleteAndReturn(ApiResponses.InvalidPayload(
                    new SetupLayeredAuthenticateMethodResponse(false),
                    nameof(SetupLayeredAuthenticateMethodRequest.contact),
                    "email two-factor setup must use the account email address."));
            }
        }

        string phoneNumber = payload.method == TwoFactorAuthMethod.SMS_KEY
            ? NormalizeTwoFactorSmsContact(payload.contact)
            : string.Empty;
        string? phoneCountryCode = payload.method == TwoFactorAuthMethod.SMS_KEY
            ? payload.countryCode!.Value.ToString(CultureInfo.InvariantCulture)
            : null;
        string smsDestination = payload.method == TwoFactorAuthMethod.SMS_KEY
            ? BuildSmsSetupDestination(phoneNumber, payload.countryCode!.Value)
            : string.Empty;

        TwoFactorSetupCommandResult? persisted = await _accountRepo.BeginTwoFactorSetup(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload.method,
            codeHash,
            moment,
            expiration,
            payload.method == TwoFactorAuthMethod.EMAIL ? emailAddress : null,
            payload.method == TwoFactorAuthMethod.SMS_KEY ? phoneNumber : null,
            phoneCountryCode,
            authId: null,
            payload.required);

        if (persisted == null)
        {
            return await CompleteAndReturn(SerializeTwoFactorSetup(
                false,
                StatusCodes.Status500InternalServerError,
                TwoFactorSetupPersistenceFailedCode));
        }

        if (!persisted.Result)
        {
            string failureCode = string.IsNullOrWhiteSpace(persisted.Code)
                ? TwoFactorSetupFailedCode
                : persisted.Code;
            return await CompleteAndReturn(SerializeTwoFactorSetup(
                false,
                TwoFactorSetupStatus(failureCode),
                failureCode));
        }

        bool delivered;
        try
        {
            delivered = await SendTwoFactorSetupChallenge(payload.method, emailAddress, smsDestination, codeKey);
        }
        catch
        {
            delivered = false;
        }

        if (!delivered)
        {
            DbCommandResult? cancelled = await _accountRepo.CancelTwoFactorSetup(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                payload.method,
                codeHash);

            string failureCode = cancelled?.Result == true
                ? TwoFactorSetupProviderFailedCode
                : TwoFactorSetupCleanupFailedCode;

            return await CompleteAndReturn(SerializeTwoFactorSetup(
                false,
                StatusCodes.Status500InternalServerError,
                failureCode));
        }

        string successCode = string.IsNullOrWhiteSpace(persisted.Code)
            ? TwoFactorSetupPendingCode
            : persisted.Code;

        return await CompleteAndReturn(SerializeTwoFactorSetup(
            true,
            TwoFactorSetupStatus(successCode),
            successCode));
    }
    [HttpPost("verifytwofactormethod")]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<LayeredAuthenticateResponse>>> VerifyTwoFactorMethod([FromBody] VerifyLayeredAuthenticateMethodRequest payload)
    {
        var verifyValidation = ValidateVerifyTwoFactorMethodRequest(payload);
        if (verifyValidation != null)
        {
            return ToActionResult(verifyValidation);
        }

        if (!TryGetAuthenticatedSession(out _, out ActiveSession activeSession))
        {
            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: StatusCodes.Status401Unauthorized,
                code: HttpMessage.AUTHENTICATION_EXPIRED.ToString()));
        }

        ApiOutcome<LayeredAuthenticateResponse>? abusePolicy = await CheckTwoFactorSetupVerifyAttemptPolicy(activeSession, payload.method);
        if (abusePolicy != null)
        {
            return ToActionResult(abusePolicy);
        }

        Instant moment = SystemClock.Instance.GetCurrentInstant();
        string codeHash = TwoFactorChallengeCodeUtility.Hash(payload.codeKey.Trim(), _loginSettings.TwoFactorChallengePepper);
        short maxAttempts = (short)Math.Clamp(_loginSettings.TwoAuthRetryLimit, 1, short.MaxValue);

        TwoFactorSetupVerificationCommandResult? verified = await _accountRepo.VerifyTwoFactorSetup(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload.method,
            codeHash,
            maxAttempts,
            moment);

        if (verified == null)
        {
            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: StatusCodes.Status500InternalServerError,
                code: TwoFactorSetupVerifyPersistenceFailedCode));
        }

        if (verified.Result)
        {
            await ResetTwoFactorSetupVerifyAttemptPolicy(activeSession, payload.method);
            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.SUCCESS,
                statusCode: StatusCodes.Status200OK,
                code: string.IsNullOrWhiteSpace(verified.Code) ? TwoFactorSetupVerifiedCode : verified.Code));
        }

        string failureCode = string.IsNullOrWhiteSpace(verified.Code)
            ? TwoFactorSetupFailedCode
            : verified.Code;

        return ToActionResult(SerializeTwoFactorAuthenticate(
            TwoFactorSetupVerifyOutcome(failureCode),
            statusCode: TwoFactorSetupVerifyStatus(failureCode),
            code: failureCode));
    }
    [HttpPost("twofactor/method/remove")]
    [ProducesResponseType(typeof(ApiResponse<RemoveTwoFactorMethodResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<RemoveTwoFactorMethodResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<RemoveTwoFactorMethodResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<RemoveTwoFactorMethodResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<RemoveTwoFactorMethodResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<RemoveTwoFactorMethodResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<RemoveTwoFactorMethodResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<RemoveTwoFactorMethodResponse>>> RemoveTwoFactorMethod([FromBody] RemoveTwoFactorMethodRequest? payload)
    {
        var removeValidation = ValidateRemoveTwoFactorMethodRequest(payload);
        if (removeValidation != null)
        {
            return ToActionResult(removeValidation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(SerializeRemoveTwoFactorMethod(
                false,
                HttpMessage.AUTHENTICATION_FAILED,
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString(),
                payload!.method));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/twofactor/method/remove", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(
            idempotency,
            new RemoveTwoFactorMethodResponse(false, HttpMessage.TWO_FACTOR_METHOD_REMOVE_FAILED, payload!.method));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (statusCode, code) => new RemoveTwoFactorMethodResponse(
                statusCode >= StatusCodes.Status200OK && statusCode < StatusCodes.Status300MultipleChoices,
                RemoveTwoFactorMethodMessage(code),
                payload!.method));
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<RemoveTwoFactorMethodResponse>>> CompleteAndReturn(ApiOutcome<RemoveTwoFactorMethodResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        IAccountSensitiveActionService? sensitiveActionService = HttpContext.RequestServices.GetService<IAccountSensitiveActionService>();
        if (sensitiveActionService is null)
        {
            return await CompleteAndReturn(SerializeRemoveTwoFactorMethod(
                false,
                HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,
                StatusCodes.Status500InternalServerError,
                AccountSensitiveActionService.TokenValidationFailedCode,
                payload!.method));
        }

        SensitiveActionValidationResult tokenValidation = await ValidateSensitiveActionToken(
            sensitiveActionService,
            activeSession,
            hashedAccessToken,
            consume: true,
            purpose: SensitiveActionPurpose.TWO_FACTOR_METHOD_REMOVE);
        if (!tokenValidation.Succeeded)
        {
            int statusCode = MissingSensitiveActionToken() ? StatusCodes.Status428PreconditionRequired : StatusCodes.Status401Unauthorized;
            return await CompleteAndReturn(SerializeRemoveTwoFactorMethod(
                false,
                tokenValidation.Result,
                statusCode,
                tokenValidation.Code,
                payload!.method));
        }

        TwoFactorMethodRemovalCommandResult? removed = await _accountRepo.RemoveTwoFactorMethod(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!.method,
            SystemClock.Instance.GetCurrentInstant());

        if (removed == null)
        {
            return await CompleteAndReturn(SerializeRemoveTwoFactorMethod(
                false,
                HttpMessage.TWO_FACTOR_METHOD_REMOVE_FAILED,
                StatusCodes.Status500InternalServerError,
                TwoFactorMethodRemoveFailedCode,
                payload.method));
        }

        return await CompleteAndReturn(SerializeRemoveTwoFactorMethod(
            removed.Result,
            RemoveTwoFactorMethodMessage(removed.Code),
            RemoveTwoFactorMethodStatus(removed.Code),
            removed.Code,
            removed.RemovedMethod,
            removed.TwoFactorAuthMethods.ToList(),
            removed.AvailableTwoFactorAuthConfigurations.ToList()));
    }


    [AllowAnonymous]
    [HttpPost("twofactor/select")]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateMethodsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateMethodsResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateMethodsResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateMethodsResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<LayeredAuthenticateMethodsResponse>>> SelectTwoFactorConfiguration([FromBody] SelectTwoFactorConfigurationRequest payload)
    {
        var selectionValidation = ValidateSelectTwoFactorConfigurationRequest(payload);
        if (selectionValidation != null)
        {
            return ToActionResult(selectionValidation);
        }

        var pendingSessionResult = await LoadValidTwoFactorSession(payload.twoFactorAccessToken);
        if (pendingSessionResult.FailureReason != null || pendingSessionResult.HashedPreAuthToken == null || pendingSessionResult.Session == null)
        {
            return ToActionResult(SerializeTwoFactorMethod(
                false,
                pendingSessionResult.FailureReason ?? HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED,
                statusCode: pendingSessionResult.StatusCode,
                code: pendingSessionResult.Code));
        }

        TwoFactorSession session = pendingSessionResult.Session;
        string hashedPreAuthToken = pendingSessionResult.HashedPreAuthToken;

        if (session.state != TwoFactorSessionState.SelectionRequired || session.selectedConfiguration.HasValue)
        {
            return ToActionResult(SerializeTwoFactorMethod(
                false,
                HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED,
                statusCode: StatusCodes.Status400BadRequest,
                code: TwoFactorSelectionAlreadyMadeCode,
                session: session));
        }

        if (!CanSelectConfiguration(session, payload.configuration))
        {
            return ToActionResult(TwoFactorConfigurationNotAvailable());
        }

        Instant moment = SystemClock.Instance.GetCurrentInstant();
        if (IsCutOffExpired(session, moment))
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_EXPIRED));
        }

        if (session.nextChallengeAllowedAt.HasValue && session.nextChallengeAllowedAt.Value > moment)
        {
            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT, session: session));
        }

        if (session.challengeResends >= _loginSettings.TwoAuthRetryLimit)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED, session: session));
        }

        StoreSelectedTwoFactorConfiguration(session, payload.configuration);
        short chosenDestination = payload.destination ?? 0;
        TwoFactorAuthMethod? currentRequiredMethod = session.currentExpectedMethod;
        if (currentRequiredMethod == null || currentRequiredMethod == TwoFactorAuthMethod.NONE)
        {
            return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSelectionPersistenceFailedCode));
        }

        TwoFactorChallengePreparationResult challengePreparation = await PrepareSelectedTwoFactorChallenge(
            session,
            chosenDestination,
            moment,
            hashedPreAuthToken);

        if (challengePreparation == TwoFactorChallengePreparationResult.InvalidDestination)
        {
            return ToActionResult(SerializeTwoFactorMethod(
                false,
                HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED,
                statusCode: StatusCodes.Status400BadRequest,
                code: TwoFactorInvalidDestinationCode,
                session: session));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.ProviderFailed)
        {
            return ToActionResult(SerializeTwoFactorMethod(
                false,
                HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED,
                statusCode: StatusCodes.Status500InternalServerError,
                code: TwoFactorProviderFailedCode,
                session: session));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.ProviderCleanupFailed)
        {
            return ToActionResult(TwoFactorMethodServerFailure(TwoFactorChallengeCleanupFailedCode));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.PersistenceFailed)
        {
            return ToActionResult(TwoFactorMethodServerFailure(TwoFactorDurableChallengePersistenceFailedCode));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.Cooldown)
        {
            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT, session: session));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.RetryLimit)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED, session: session));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.Expired)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_EXPIRED, session: session));
        }

        TimeSpan remainingTtl = RemainingTtl(session, moment);
        PendingSessionWriteResult stored = await SafeSetPendingTwoFactorSession(hashedPreAuthToken, session, remainingTtl);
        if (stored.Stored != true)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(TwoFactorMethodServerFailure(TwoFactorChallengePersistenceFailedCode));
        }

        return ToActionResult(SerializeTwoFactorMethod(
            true,
            WaitingMessageForTwoFactorMethod(currentRequiredMethod.Value),
            currentRequiredMethod,
            session.challengeExpiration,
            session.chosenDestination,
            session: session));
    }


    [NonAction]
    public async Task<ActionResult<ApiResponse<LayeredAuthenticateMethodsResponse>>> TwoFactorMethod([FromBody] LayeredAuthenticateMethodsRequest payload)
    {
        var methodValidation = ValidateTwoFactorMethodRequest(payload);
        if (methodValidation != null)
        {
            return ToActionResult(methodValidation);
        }

        var pendingSessionResult = await LoadValidTwoFactorSession();
        if (pendingSessionResult.FailureReason != null || pendingSessionResult.HashedPreAuthToken == null || pendingSessionResult.Session == null)
        {
            return ToActionResult(SerializeTwoFactorMethod(
                false,
                pendingSessionResult.FailureReason ?? HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED,
                statusCode: pendingSessionResult.StatusCode,
                code: pendingSessionResult.Code));
        }

        TwoFactorSession session = pendingSessionResult.Session;
        string hashedPreAuthToken = pendingSessionResult.HashedPreAuthToken;

        if (!session.methods.Contains(payload.method))
        {
            return ToActionResult(TwoFactorMethodNotAvailable());
        }

        Instant moment = SystemClock.Instance.GetCurrentInstant();
        if (IsCutOffExpired(session, moment))
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_EXPIRED));
        }

        if (session.nextChallengeAllowedAt.HasValue && session.nextChallengeAllowedAt.Value > moment)
        {
            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT));
        }

        if (session.challengeResends >= _loginSettings.TwoAuthRetryLimit)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED));
        }

        short chosenDestination = payload.destination ?? 0;
        HttpMessage waitingStatus;
        TwoFactorChallengePreparationResult challengePreparation;

        switch (payload.method)
        {
            case TwoFactorAuthMethod.EMAIL:
                challengePreparation = await PrepareEmailChallenge(session, chosenDestination, moment, hashedPreAuthToken);
                waitingStatus = HttpMessage.TWOFACTOR_WAITING_INTRA_EMAIL;
                break;

            case TwoFactorAuthMethod.SMS_KEY:
                challengePreparation = await PrepareSmsChallenge(session, chosenDestination, moment, hashedPreAuthToken);
                waitingStatus = HttpMessage.TWOFACTOR_WAITING_SMS_KEY;
                break;

            case TwoFactorAuthMethod.AUTHENTICATOR_APP:
                challengePreparation = await PrepareAuthenticatorAppChallenge(session, moment, hashedPreAuthToken);
                waitingStatus = HttpMessage.TWOFACTOR_WAITING_AUTHENTICATOR_APP;
                break;

            default:
                return ToActionResult(ApiResponses.InvalidPayload(
                    new LayeredAuthenticateMethodsResponse(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED),
                    nameof(LayeredAuthenticateMethodsRequest.method),
                    SupportedTwoFactorMethodRequiredMessage));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.InvalidDestination)
        {
            return ToActionResult(SerializeTwoFactorMethod(
                false,
                HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED,
                statusCode: StatusCodes.Status400BadRequest,
                code: TwoFactorInvalidDestinationCode));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.ProviderFailed)
        {
            return ToActionResult(SerializeTwoFactorMethod(
                false,
                HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED,
                statusCode: StatusCodes.Status500InternalServerError,
                code: TwoFactorProviderFailedCode));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.ProviderCleanupFailed)
        {
            return ToActionResult(TwoFactorMethodServerFailure(TwoFactorChallengeCleanupFailedCode));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.PersistenceFailed)
        {
            return ToActionResult(TwoFactorMethodServerFailure(TwoFactorDurableChallengePersistenceFailedCode));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.Cooldown)
        {
            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.RetryLimit)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED));
        }

        if (challengePreparation == TwoFactorChallengePreparationResult.Expired)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorMethod(false, HttpMessage.AUTHENTICATION_EXPIRED));
        }

        TimeSpan remainingTtl = RemainingTtl(session, moment);
        PendingSessionWriteResult stored = await SafeSetPendingTwoFactorSession(hashedPreAuthToken, session, remainingTtl);
        if (stored.Stored != true)
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(TwoFactorMethodServerFailure(TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(TwoFactorMethodServerFailure(TwoFactorChallengePersistenceFailedCode));
        }

        return ToActionResult(SerializeTwoFactorMethod(true, waitingStatus, payload.method, session.challengeExpiration, session.chosenDestination, session: session));
    }
    [AllowAnonymous]
    [HttpPost("twofactorauth")]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<LayeredAuthenticateResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<LayeredAuthenticateResponse>>> TwoFactorAuthenticate([FromBody] LayeredAuthenticateRequest payload)
    {
        var authValidation = ValidateTwoFactorAuthenticateRequest(payload);
        if (authValidation != null)
        {
            return ToActionResult(authValidation);
        }

        var pendingSessionResult = await LoadValidTwoFactorSession();
        if (pendingSessionResult.FailureReason != null || pendingSessionResult.HashedPreAuthToken == null || pendingSessionResult.Session == null)
        {
            HttpMessage failureReason = pendingSessionResult.FailureReason ?? HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED;
            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: pendingSessionResult.StatusCode ?? TwoFactorAuthenticateStatus(failureReason),
                code: pendingSessionResult.Code ?? failureReason.ToString()));
        }

        TwoFactorSession session = pendingSessionResult.Session;
        string hashedPreAuthToken = pendingSessionResult.HashedPreAuthToken;
        Instant moment = SystemClock.Instance.GetCurrentInstant();
        if (IsCutOffExpired(session, moment))
        {
            PendingSessionRevokeResult revoked = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            if (!revoked.Revoked)
            {
                return ToActionResult(SerializeTwoFactorAuthenticate(
                    TwoFactorAuthOutcome.FAILURE,
                    statusCode: StatusCodes.Status500InternalServerError,
                    code: TwoFactorSessionRevokeFailedCode));
            }

            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: StatusCodes.Status401Unauthorized,
                code: HttpMessage.AUTHENTICATION_EXPIRED.ToString()));
        }

        TwoFactorChallengeVerification challengeVerification = await VerifyTwoFactorChallenge(payload, session, moment, hashedPreAuthToken);
        if (challengeVerification.Outcome != TwoFactorAuthOutcome.SUCCESS)
        {
            int? failureStatusCode = challengeVerification.StatusCode
                ?? (challengeVerification.FailureReason == null
                    ? null
                    : TwoFactorAuthenticateStatus(challengeVerification.FailureReason.Value));
            string? failureCode = challengeVerification.Code ?? challengeVerification.FailureReason?.ToString();
            return ToActionResult(SerializeTwoFactorAuthenticate(
                challengeVerification.Outcome,
                statusCode: failureStatusCode,
                code: failureCode,
                session: session));
        }

        TwoFactorProofAdvanceResult proofAdvance = await AdvanceTwoFactorSessionAfterAcceptedProof(session, moment, hashedPreAuthToken);
        if (proofAdvance.FailureReason != null || proofAdvance.StatusCode != null || proofAdvance.Code != null)
        {
            int? failureStatusCode = proofAdvance.StatusCode
                ?? (proofAdvance.FailureReason == null
                    ? null
                    : TwoFactorAuthenticateStatus(proofAdvance.FailureReason.Value));
            string? failureCode = proofAdvance.Code ?? proofAdvance.FailureReason?.ToString();
            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: failureStatusCode,
                code: failureCode,
                session: session));
        }

        if (!proofAdvance.Complete)
        {
            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.SUCCESS,
                statusCode: StatusCodes.Status200OK,
                code: HttpMessage.AUTHENTICATION_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED.ToString(),
                session: session));
        }

        byte[] finalRefreshToken = RandomNumberGenerator.GetBytes(_jwtSettings.RefreshTokenBytes);
        string finalAccessToken = _jwtUtility.GenerateAccessToken(finalRefreshToken, session.webKey);
        string? finalHashedAccessToken = HashAccessToken(finalAccessToken);
        if (finalHashedAccessToken == null)
        {
            return ToActionResult(SerializeTwoFactorAuthenticate(TwoFactorAuthOutcome.FAILURE, statusCode: StatusCodes.Status500InternalServerError));
        }

        ActiveSession activeSession = BuildPromotedActiveSession(session, finalRefreshToken, moment, out Period cachePeriod);
        bool isRotatingExistingActiveSession = !string.IsNullOrWhiteSpace(session.priorActiveAccessTokenHash);
        string? priorActiveAccessTokenHash = session.priorActiveAccessTokenHash;

        if (!isRotatingExistingActiveSession)
        {
            DbCommandResult? promoted = await SafePromoteTwoFactorNewLogin(
                session.accountId,
                hashedPreAuthToken,
                session.accountSecurityStamp,
                finalHashedAccessToken,
                activeSession.toSession());
            if (promoted?.Result != true)
            {
                return ToActionResult(SerializeTwoFactorAuthenticate(
                    TwoFactorAuthOutcome.FAILURE,
                    statusCode: StatusCodes.Status500InternalServerError,
                    code: promoted?.Code ?? ActiveSessionDbPersistenceFailedCode));
            }

            ActiveCacheWriteResult cached = await SafeSetActiveSession(finalHashedAccessToken, activeSession, cachePeriod.ToDuration().ToTimeSpan());
            if (!cached.Stored)
            {
                // CORE-2: DB promotion is already authoritative. Keep the final session and let
                // later middleware DB fallback hydrate Redis instead of rolling back a valid login.
            }

            // DB promotion is authoritative and atomic: final session persistence plus pending
            // account marker cleanup succeed or fail together. Redis pending cleanup is best-effort.
            _ = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
            return ToActionResult(SerializeTwoFactorAuthenticate(TwoFactorAuthOutcome.SUCCESS, finalAccessToken));
        }

        DbCommandResult? rotationPromoted = await SafePromoteTwoFactorRotationLogin(
            session.accountId,
            hashedPreAuthToken,
            session.accountSecurityStamp,
            priorActiveAccessTokenHash!,
            finalHashedAccessToken,
            activeSession.toSession());
        if (rotationPromoted?.Result != true)
        {
            return ToActionResult(SerializeTwoFactorAuthenticate(
                TwoFactorAuthOutcome.FAILURE,
                statusCode: StatusCodes.Status500InternalServerError,
                code: rotationPromoted?.Code ?? TwoFactorRotationAfterFinalizationFailedCode));
        }

        ActiveCacheWriteResult rotationCached = await SafeSetActiveSession(finalHashedAccessToken, activeSession, cachePeriod.ToDuration().ToTimeSpan());
        if (!rotationCached.Stored)
        {
            // CORE-2: DB rotation promotion is authoritative. Keep the final session and let
            // later middleware DB fallback hydrate Redis instead of expiring the promoted row.
        }

        _ = await SafeRevokePendingTwoFactorSession(hashedPreAuthToken);
        // The DB rotation is authoritative; old active-cache cleanup is best-effort.
        _ = await SafeRevokeActiveSession(priorActiveAccessTokenHash!);

        return ToActionResult(SerializeTwoFactorAuthenticate(TwoFactorAuthOutcome.SUCCESS, finalAccessToken));
    }


    private static readonly IReadOnlyList<string> SupportedAuthenticatorApps = new[]
    {
        "Google Authenticator",
        "Microsoft Authenticator",
        "1Password",
        "Bitwarden",
        "Aegis",
        "FreeOTP"
    };

    private async Task<SensitiveActionValidationResult> ValidateSensitiveActionToken(
        IAccountSensitiveActionService service,
        ActiveSession activeSession,
        string sessionBindingHash,
        bool consume,
        SensitiveActionPurpose purpose = SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP)
    {
        string token = Request.Headers.TryGetValue(SensitiveActionTokenConstants.HeaderName, out var values)
            ? values.FirstOrDefault() ?? string.Empty
            : string.Empty;

        return await service.ValidateAsync(
            new SensitiveActionValidationCommand(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                sessionBindingHash,
                token,
                purpose,
                consume),
            HttpContext.RequestAborted);
    }

    private bool MissingSensitiveActionToken()
    {
        return !Request.Headers.TryGetValue(SensitiveActionTokenConstants.HeaderName, out var values)
            || string.IsNullOrWhiteSpace(values.FirstOrDefault());
    }

    private static ApiOutcome<StartAuthenticatorAppSetupResponse> SerializeAuthenticatorSetupStart(
        bool status,
        HttpMessage result,
        int statusCode,
        string code)
    {
        return new ApiOutcome<StartAuthenticatorAppSetupResponse>(
            new StartAuthenticatorAppSetupResponse(result, status)
            {
                supportedAuthenticatorApps = SupportedAuthenticatorApps
            },
            statusCode,
            code);
    }

    private static ApiOutcome<VerifyAuthenticatorAppSetupResponse> SerializeAuthenticatorSetupVerify(
        bool status,
        HttpMessage result,
        int statusCode,
        string code,
        string? accessToken = null)
    {
        return new ApiOutcome<VerifyAuthenticatorAppSetupResponse>(
            new VerifyAuthenticatorAppSetupResponse(result, status, accessToken),
            statusCode,
            code);
    }

    private static ApiOutcome<CancelAuthenticatorAppSetupResponse> SerializeAuthenticatorSetupCancel(
        bool status,
        HttpMessage result,
        int statusCode,
        string code)
    {
        return new ApiOutcome<CancelAuthenticatorAppSetupResponse>(
            new CancelAuthenticatorAppSetupResponse(result, status),
            statusCode,
            code);
    }

    private static ApiOutcome<RemoveTwoFactorMethodResponse> SerializeRemoveTwoFactorMethod(
        bool outcome,
        HttpMessage result,
        int statusCode,
        string code,
        TwoFactorAuthMethod? removedMethod = null,
        List<TwoFactorAuthMethod>? twoFactorAuthMethods = null,
        List<TwoFactorAuthConfiguration>? availableTwoFactorAuthConfigurations = null)
    {
        return new ApiOutcome<RemoveTwoFactorMethodResponse>(
            new RemoveTwoFactorMethodResponse(
                outcome,
                result,
                removedMethod,
                twoFactorAuthMethods,
                availableTwoFactorAuthConfigurations),
            statusCode,
            code);
    }

    private static HttpMessage RemoveTwoFactorMethodMessage(string? code)
    {
        return code switch
        {
            TwoFactorMethodRemovedCode => HttpMessage.TWO_FACTOR_METHOD_REMOVED,
            TwoFactorMethodNotConfiguredCode => HttpMessage.TWO_FACTOR_METHOD_NOT_CONFIGURED,
            TwoFactorMethodRemoveUnsupportedMethodCode => HttpMessage.TWO_FACTOR_METHOD_REMOVE_UNSUPPORTED_METHOD,
            AccountSecurityStampMismatchCode => HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH,
            AccountNotFoundCode => HttpMessage.ACCOUNT_NOT_FOUND,
            _ when string.Equals(code, AccountSensitiveActionService.TokenValidationFailedCode, StringComparison.Ordinal) => HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,
            _ => HttpMessage.TWO_FACTOR_METHOD_REMOVE_FAILED
        };
    }

    private static int RemoveTwoFactorMethodStatus(string? code)
    {
        return code switch
        {
            TwoFactorMethodRemovedCode => StatusCodes.Status200OK,
            TwoFactorMethodNotConfiguredCode => StatusCodes.Status404NotFound,
            TwoFactorMethodRemoveUnsupportedMethodCode => StatusCodes.Status400BadRequest,
            AccountSecurityStampMismatchCode => StatusCodes.Status401Unauthorized,
            AccountNotFoundCode => StatusCodes.Status404NotFound,
            _ when string.Equals(code, AccountSensitiveActionService.TokenValidationFailedCode, StringComparison.Ordinal) => StatusCodes.Status401Unauthorized,
            _ => StatusCodes.Status500InternalServerError
        };
    }


    private static HttpMessage AuthenticatorSetupMessage(string? code)
    {
        return code switch
        {
            AuthenticatorAppSetupService.SetupStartedCode => HttpMessage.AUTHENTICATOR_SETUP_STARTED,
            AuthenticatorAppSetupService.SetupVerifiedSessionRotatedCode => HttpMessage.AUTHENTICATOR_SETUP_VERIFIED,
            AuthenticatorAppSetupService.SetupCancelledCode => HttpMessage.AUTHENTICATOR_SETUP_CANCELLED,
            AuthenticatorAppSetupService.AuthenticatorAppAlreadyAttachedCode => HttpMessage.TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED,
            "AUTHENTICATOR_SETUP_DUPLICATE" => HttpMessage.TWO_FACTOR_AUTHENTICATOR_APP_ALREADY_ATTACHED,
            "AUTHENTICATOR_SETUP_ALREADY_CANCELLED_OR_MISSING" => HttpMessage.AUTHENTICATOR_SETUP_CANCELLED,
            AccountSecurityStampMismatchCode => HttpMessage.ACCOUNT_SECURITY_STAMP_MISMATCH,
            _ when string.Equals(code, HttpMessage.AUTHENTICATION_EXPIRED.ToString(), StringComparison.Ordinal) => HttpMessage.AUTHENTICATION_EXPIRED,
            _ when string.Equals(code, HttpMessage.AUTHENTICATION_FAILED.ToString(), StringComparison.Ordinal) => HttpMessage.AUTHENTICATION_FAILED,
            _ when string.Equals(code, AccountSensitiveActionService.TokenValidationFailedCode, StringComparison.Ordinal) => HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,
            _ => HttpMessage.AUTHENTICATOR_SETUP_FAILED
        };
    }

    private static int AuthenticatorSetupStatus(string? code)
    {
        return code switch
        {
            AuthenticatorAppSetupService.SetupStartedCode => StatusCodes.Status202Accepted,
            AuthenticatorAppSetupService.SetupVerifiedSessionRotatedCode => StatusCodes.Status200OK,
            AuthenticatorAppSetupService.SetupCancelledCode => StatusCodes.Status200OK,
            "AUTHENTICATOR_SETUP_ALREADY_CANCELLED_OR_MISSING" => StatusCodes.Status200OK,
            AccountSecurityStampMismatchCode => StatusCodes.Status401Unauthorized,
            "ACCOUNT_NOT_VERIFIED" => StatusCodes.Status401Unauthorized,
            "ACCOUNT_CUT_OFF_EXPIRED" => StatusCodes.Status401Unauthorized,
            "OLD_SESSION_EXPIRED" => StatusCodes.Status401Unauthorized,
            "OLD_SESSION_NOT_FOUND" => StatusCodes.Status401Unauthorized,
            "AUTHENTICATOR_SETUP_ATTEMPT_LIMIT" => StatusCodes.Status429TooManyRequests,
            "AUTHENTICATOR_SETUP_PROVIDER_UNSUPPORTED" => StatusCodes.Status400BadRequest,
            "AUTHENTICATOR_SETUP_INVALID_REQUEST" => StatusCodes.Status400BadRequest,
            "AUTHENTICATOR_SETUP_INVALID_TOKEN" => StatusCodes.Status400BadRequest,
            "AUTHENTICATOR_SETUP_NOT_FOUND" => StatusCodes.Status400BadRequest,
            "AUTHENTICATOR_SETUP_EXPIRED" => StatusCodes.Status400BadRequest,
            "AUTHENTICATOR_SETUP_INCORRECT" => StatusCodes.Status400BadRequest,
            "AUTHENTICATOR_SETUP_INVALID_SECRET" => StatusCodes.Status400BadRequest,
            "TOTP_INVALID_SHAPE" => StatusCodes.Status400BadRequest,
            "TOTP_REPLAY_DETECTED" => StatusCodes.Status409Conflict,
            AuthenticatorAppSetupService.AuthenticatorAppAlreadyAttachedCode => StatusCodes.Status409Conflict,
            "AUTHENTICATOR_SETUP_DUPLICATE" => StatusCodes.Status409Conflict,
            _ => StatusCodes.Status500InternalServerError
        };
    }

}
