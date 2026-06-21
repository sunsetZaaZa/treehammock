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
public sealed class AccountSessionController : AccountControllerBase
{
    public AccountSessionController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
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


    [HttpPost("reauthenticate")]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ReauthenticateResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<ReauthenticateResponse>>> Reauthenticate([FromBody] ReauthenticateRequest? payload)
    {
        var validation = ValidateReauthenticateRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ReauthenticateResponse>(
                new ReauthenticateResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        IAccountSensitiveActionService? sensitiveActionService = HttpContext.RequestServices.GetService<IAccountSensitiveActionService>();
        if (sensitiveActionService is null)
        {
            return ToActionResult(new ApiOutcome<ReauthenticateResponse>(
                new ReauthenticateResponse(HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUE_FAILED),
                StatusCodes.Status500InternalServerError,
                AccountSensitiveActionService.TokenIssueFailedCode));
        }

        SensitiveActionIssueResult result = await sensitiveActionService.ReauthenticateAsync(
            new SensitiveActionReauthenticationCommand(
                activeSession.accountId,
                activeSession.accountSecurityStamp,
                hashedAccessToken,
                payload!.password,
                payload.purpose),
            HttpContext.RequestAborted);

        int statusCode = result.Succeeded
            ? StatusCodes.Status200OK
            : result.Result == HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED
                ? StatusCodes.Status401Unauthorized
                : StatusCodes.Status500InternalServerError;

        return ToActionResult(new ApiOutcome<ReauthenticateResponse>(
            new ReauthenticateResponse(
                result.Result,
                result.Token,
                result.Purpose,
                result.Expiration),
            statusCode,
            result.Code));
    }

    [HttpPost("logoff")]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AuthenticateLogoffResponse>>> LogoffAccount([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AuthenticateLogoffRequest? payload = null)
    {
        var validation = ValidateLogoffAccountRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AuthenticateLogoffResponse>(
                new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/logoff");
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (_, code) => new AuthenticateLogoffResponse(LogoffReplayMessage(code)));
        if (idempotencyReplay != null)
        {
            if (idempotencyReplay.StatusCode >= StatusCodes.Status200OK && idempotencyReplay.StatusCode < StatusCodes.Status300MultipleChoices)
            {
                Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            }

            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AuthenticateLogoffResponse>>> CompleteAndReturn(ApiOutcome<AuthenticateLogoffResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        DbCommandResult? dbResult = await SafeLogoutCurrentSession(
            activeSession.accountId,
            hashedAccessToken,
            activeSession.accountSecurityStamp);

        if (dbResult?.Result != true)
        {
            return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffResponse>(
                new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED),
                AuthStateConflictStatus(dbResult?.Code),
                dbResult?.Code ?? LogoffFailedCode));
        }

        ActiveSessionRevokeResult cacheResult = await SafeRevokeActiveSession(hashedAccessToken);
        Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();

        return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffResponse>(
            new AuthenticateLogoffResponse(HttpMessage.AUTHENTICATION_LOGOFF_SUCCEEDED),
            StatusCodes.Status200OK,
            cacheResult.Revoked ? LogoffSucceededCode : LogoffCacheRevokeFailedCode));
    }
    [HttpPost("logoff/all")]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AuthenticateLogoffAllResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AuthenticateLogoffAllResponse>>> LogoffAllAccount([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AuthenticateLogoffAllRequest? payload = null)
    {
        var validation = ValidateLogoffAllAccountRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AuthenticateLogoffAllResponse>(
                new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/logoff/all", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (_, code) => new AuthenticateLogoffAllResponse(LogoffAllReplayMessage(code)));
        if (idempotencyReplay != null)
        {
            if (idempotencyReplay.StatusCode >= StatusCodes.Status200OK && idempotencyReplay.StatusCode < StatusCodes.Status300MultipleChoices)
            {
                Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            }

            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AuthenticateLogoffAllResponse>>> CompleteAndReturn(ApiOutcome<AuthenticateLogoffAllResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        AccountStampRotationResult? dbResult = await SafeLogoutAllSessions(
            activeSession.accountId,
            activeSession.accountSecurityStamp);

        if (dbResult?.Result != true)
        {
            return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffAllResponse>(
                new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_FAILED),
                AuthStateConflictStatus(dbResult?.Code),
                dbResult?.Code ?? LogoffAllFailedCode));
        }

        _ = await SafeRevokeActiveSession(hashedAccessToken);
        Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();

        return await CompleteAndReturn(new ApiOutcome<AuthenticateLogoffAllResponse>(
            new AuthenticateLogoffAllResponse(HttpMessage.AUTHENTICATION_LOGOFF_ALL_SUCCEEDED),
            StatusCodes.Status200OK,
            LogoffAllSucceededCode));
    }
    [HttpGet("sessions")]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionsResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionsResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountSessionsResponse>>> ListActiveSessions()
    {
        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountSessionsResponse>(
                new AccountSessionsResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        IReadOnlyList<AccountSessionSummary>? sessions = await SafeListActiveSessions(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            hashedAccessToken);

        if (sessions == null)
        {
            return ToActionResult(new ApiOutcome<AccountSessionsResponse>(
                new AccountSessionsResponse(HttpMessage.AUTHENTICATION_SESSIONS_LOOKUP_FAILED),
                StatusCodes.Status500InternalServerError,
                SessionsLookupFailedCode));
        }

        return ToActionResult(new ApiOutcome<AccountSessionsResponse>(
            new AccountSessionsResponse(HttpMessage.AUTHENTICATION_SESSIONS_LISTED, sessions),
            StatusCodes.Status200OK,
            SessionsListedCode));
    }
    [HttpPost("sessions/revoke")]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AccountSessionRevokeResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AccountSessionRevokeResponse>>> RevokeSession([FromBody] AccountSessionRevokeRequest? payload)
    {
        var validation = ValidateRevokeSessionRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountSessionRevokeResponse>(
                new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/sessions/revoke", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (_, code) => new AccountSessionRevokeResponse(SessionRevokeReplayMessage(code)));
        if (idempotencyReplay != null)
        {
            if (string.Equals(idempotencyReplay.Code, CurrentSessionRevokeSucceededCode, StringComparison.Ordinal) ||
                string.Equals(idempotencyReplay.Code, SessionRevokeCacheRevokeFailedCode, StringComparison.Ordinal))
            {
                Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            }

            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AccountSessionRevokeResponse>>> CompleteAndReturn(ApiOutcome<AccountSessionRevokeResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        DbCommandResult? dbResult = await SafeRevokeSessionForAccount(
            activeSession.accountId,
            payload!.sessionId,
            activeSession.accountSecurityStamp,
            hashedAccessToken);

        if (dbResult?.Result != true)
        {
            return await CompleteAndReturn(new ApiOutcome<AccountSessionRevokeResponse>(
                new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKE_FAILED),
                AuthStateConflictStatus(dbResult?.Code),
                dbResult?.Code ?? SessionRevokeFailedCode));
        }

        string responseCode = !string.IsNullOrWhiteSpace(dbResult.Code)
            ? dbResult.Code
            : SessionRevokeSucceededCode;

        if (string.Equals(dbResult.Code, CurrentSessionRevokeSucceededCode, StringComparison.Ordinal))
        {
            ActiveSessionRevokeResult cacheResult = await SafeRevokeActiveSession(hashedAccessToken);
            Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            responseCode = cacheResult.Revoked ? CurrentSessionRevokeSucceededCode : SessionRevokeCacheRevokeFailedCode;
        }

        return await CompleteAndReturn(new ApiOutcome<AccountSessionRevokeResponse>(
            new AccountSessionRevokeResponse(HttpMessage.AUTHENTICATION_SESSION_REVOKED),
            StatusCodes.Status200OK,
            responseCode));
    }

}
