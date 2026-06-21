using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
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
public sealed class AccountDeleteController : AccountControllerBase
{
    public AccountDeleteController(IAccountRepo accountRepo, ISessionRepo sessionRepo, IActiveUserCacheService activeUserCacheService, ITwoFactorSessionService twoFactorSessionService,
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

    [HttpPost("wipeout")]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> DeleteAccount([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] AccountDeleteRequest? payload = null)
    {
        var validation = ValidateDeleteAccountRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out _, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/wipeout", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (_, code) => new AccountDeleteResponse(AccountDeleteMessage(code)));
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> CompleteAndReturn(ApiOutcome<AccountDeleteResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        AccountDeleteCommandResult? dbResult = await SafeRequestAccountDelete(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload?.passPhrase);

        if (dbResult?.Result == true)
        {
            string successCode = string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeletePendingCode : dbResult.Code;
            return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(AccountDeleteMessage(successCode)),
                StatusCodes.Status202Accepted,
                successCode));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteFailedCode : dbResult.Code;
        return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
            new AccountDeleteResponse(AccountDeleteMessage(code)),
            AccountDeleteFailureStatus(code),
            code));
    }
    [AllowAnonymous]
    [HttpGet("wipeout/verify")]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> VerifyDeleteAccount([FromQuery] string? payload)
    {
        var validation = ValidateDeleteVerifyPayload(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        string deleteToken = payload!.Trim();
        AccountDeleteCommandResult? dbResult = await SafeVerifyAccountDeleteToken(deleteToken);
        if (dbResult?.Result == true)
        {
            string successCode = string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteVerifiedCode : dbResult.Code;
            return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(AccountDeleteMessage(successCode), dbResult.Workflow),
                StatusCodes.Status200OK,
                successCode));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteFailedCode : dbResult.Code;
        return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
            new AccountDeleteResponse(AccountDeleteMessage(code)),
            AccountDeleteFailureStatus(code),
            code));
    }
    [HttpPost("wipeout/finalize")]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<AccountDeleteResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> FinalizeDeleteAccount([FromBody] AccountDeleteFinalizeRequest? payload)
    {
        var validation = ValidateFinalizeDeleteRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out string hashedAccessToken, out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(HttpMessage.AUTHENTICATION_FAILED),
                StatusCodes.Status401Unauthorized,
                HttpMessage.AUTHENTICATION_FAILED.ToString()));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "account/wipeout/finalize", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new AccountDeleteResponse(HttpMessage.ACCOUNT_DELETE_FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (_, code) => new AccountDeleteResponse(AccountDeleteMessage(code)));
        if (idempotencyReplay != null)
        {
            if (idempotencyReplay.StatusCode >= StatusCodes.Status200OK && idempotencyReplay.StatusCode < StatusCodes.Status300MultipleChoices)
            {
                Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            }

            return ToActionResult(idempotencyReplay);
        }

        async Task<ActionResult<ApiResponse<AccountDeleteResponse>>> CompleteAndReturn(ApiOutcome<AccountDeleteResponse> outcome)
        {
            await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);
            return ToActionResult(outcome);
        }

        AccountDeleteCommandResult? dbResult = await SafeFinalizeAccountDelete(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!.deleteToken,
            payload.passPhrase);

        if (dbResult?.Result == true)
        {
            _ = await SafeRevokeActiveSession(hashedAccessToken);
            Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();

            string successCode = string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteSucceededCode : dbResult.Code;
            return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
                new AccountDeleteResponse(AccountDeleteMessage(successCode)),
                StatusCodes.Status200OK,
                successCode));
        }

        string code = dbResult is null || string.IsNullOrWhiteSpace(dbResult.Code) ? AccountDeleteFailedCode : dbResult.Code;
        return await CompleteAndReturn(new ApiOutcome<AccountDeleteResponse>(
            new AccountDeleteResponse(AccountDeleteMessage(code)),
            AccountDeleteFailureStatus(code),
            code));
    }

}
