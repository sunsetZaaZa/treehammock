using System.ComponentModel.DataAnnotations;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NodaTime;

using treehammock.DataLayer.Cache;
using treehammock.Models.Activation;
using treehammock.Models.Api;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Controllers;

[Authenticate]
[ApiController]
[Route("activations")]
[Produces("application/json")]
public class ActivationsController : ControllerBase
{
    private const string RequestBodyRequiredMessage = "The request body is required.";
    private const string AuthenticationFailedCode = "AUTHENTICATION_FAILED";

    private readonly IActivationService _activationService;
    private readonly IAuthenticatedMutationIdempotencyService _authenticatedMutationIdempotencyService;
    private readonly EmailAddressAttribute _emailValidator = new();

    public ActivationsController(
        IActivationService activationService,
        IAuthenticatedMutationIdempotencyService? authenticatedMutationIdempotencyService = null)
    {
        _activationService = activationService;
        _authenticatedMutationIdempotencyService = authenticatedMutationIdempotencyService ?? NoOpAuthenticatedMutationIdempotencyService.Instance;
    }

    [HttpPost("place")]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<ActivationCreationResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<ActivationCreationResponse>>> PlaceActivation([FromBody] ActivationCreationRequest? payload)
    {
        var validation = ValidateCreationRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ActivationCreationResponse>(
                new ActivationCreationResponse(Pass.UNAUTHORIZED),
                StatusCodes.Status401Unauthorized,
                AuthenticationFailedCode));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "activations/place", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new ActivationCreationResponse(Pass.FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (_, code) => new ActivationCreationResponse(ActivationPass(code)));
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        ActivationCreateResult result = await _activationService.PlaceActivation(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!,
            SystemClock.Instance.GetCurrentInstant());

        var outcome = new ApiOutcome<ActivationCreationResponse>(
            new ActivationCreationResponse(result.Result ? Pass.SUCCESSFUL : ActivationPass(result.Code)),
            ActivationStatusCode(result.Code, successStatusCode: StatusCodes.Status202Accepted),
            result.Code);
        await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);

        return ToActionResult(outcome);
    }

    [HttpPost("verify")]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status410Gone)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status429TooManyRequests)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ApiResponse<ActivationDetailsResponse>), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<ActivationDetailsResponse>>> VerifyActivation([FromBody] ActivationDetailsRequest? payload)
    {
        var validation = ValidateDetailsRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ActivationDetailsResponse>(
                EmptyDetails(Pass.UNAUTHORIZED),
                StatusCodes.Status401Unauthorized,
                AuthenticationFailedCode));
        }

        ActivationVerifyResult result = await _activationService.VerifyActivation(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!,
            SystemClock.Instance.GetCurrentInstant());

        ActivationDetailsResponse response = result.Result && result.Activation is not null
            ? new ActivationDetailsResponse(
                Pass.SUCCESSFUL,
                result.Activation.expiration.ToString(),
                (uint)result.Activation.duration,
                (uint)result.Activation.featureSet)
            : EmptyDetails(ActivationPass(result.Code));

        return ToActionResult(new ApiOutcome<ActivationDetailsResponse>(
            response,
            ActivationStatusCode(result.Code, successStatusCode: StatusCodes.Status200OK),
            result.Code));
    }

    [HttpPost("disable")]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status409Conflict)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status428PreconditionRequired)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status410Gone)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status500InternalServerError)]
    [ProducesResponseType(typeof(ApiResponse<ActivationUnSubscribeResponse>), StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<ApiResponse<ActivationUnSubscribeResponse>>> DisableActivation([FromBody] ActivationUnSubscribeRequest? payload)
    {
        var validation = ValidateUnSubscribeRequest(payload);
        if (validation != null)
        {
            return ToActionResult(validation);
        }

        if (!TryGetAuthenticatedSession(out ActiveSession activeSession))
        {
            return ToActionResult(new ApiOutcome<ActivationUnSubscribeResponse>(
                new ActivationUnSubscribeResponse(Pass.UNAUTHORIZED),
                StatusCodes.Status401Unauthorized,
                AuthenticationFailedCode));
        }

        AuthenticatedMutationIdempotencyBeginResult idempotency = await BeginAuthenticatedMutationIdempotency(activeSession, "activations/disable", requireKey: true);
        var idempotencyBlock = IdempotencyBlockingOutcome(idempotency, new ActivationUnSubscribeResponse(Pass.FAILED));
        if (idempotencyBlock != null)
        {
            return ToActionResult(idempotencyBlock);
        }

        var idempotencyReplay = IdempotencyReplayOutcome(
            idempotency,
            (_, code) => new ActivationUnSubscribeResponse(ActivationPass(code)));
        if (idempotencyReplay != null)
        {
            return ToActionResult(idempotencyReplay);
        }

        ActivationDisableResult result = await _activationService.DisableActivation(
            activeSession.accountId,
            activeSession.accountSecurityStamp,
            payload!,
            SystemClock.Instance.GetCurrentInstant());

        var outcome = new ApiOutcome<ActivationUnSubscribeResponse>(
            new ActivationUnSubscribeResponse(result.Result ? Pass.SUCCESSFUL : ActivationPass(result.Code)),
            ActivationStatusCode(result.Code, successStatusCode: StatusCodes.Status200OK),
            result.Code);
        await CompleteAuthenticatedMutationIdempotency(idempotency, outcome.StatusCode, outcome.Code);

        return ToActionResult(outcome);
    }

    private ApiOutcome<ActivationCreationResponse>? ValidateCreationRequest(ActivationCreationRequest? payload)
    {
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(
                new ActivationCreationResponse(Pass.INVALID),
                string.Empty,
                RequestBodyRequiredMessage);
        }

        payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        AddEmailValidation(
            errors,
            payload.emailAddress,
            nameof(ActivationCreationRequest.emailAddress),
            ActivationCreationRequest.MaxEmailAddressLength);

        if (!Enum.IsDefined(typeof(FeatureSet), (int)payload.featureSet))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationCreationRequest.featureSet), "A supported featureSet is required."));
        }

        if (!Enum.IsDefined(typeof(DayDuration), payload.term))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationCreationRequest.term), "A supported term is required."));
        }

        if (!Enum.IsDefined(typeof(DurationRepeat), payload.recycle))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationCreationRequest.recycle), "A supported recycle value is required."));
        }

        return errors.Count == 0
            ? null
            : ApiResponses.InvalidPayload(new ActivationCreationResponse(Pass.INVALID), errors);
    }

    private ApiOutcome<ActivationDetailsResponse>? ValidateDetailsRequest(ActivationDetailsRequest? payload)
    {
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(
                EmptyDetails(Pass.INVALID),
                string.Empty,
                RequestBodyRequiredMessage);
        }

        payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;
        payload.code = payload.code?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        AddEmailValidation(
            errors,
            payload.emailAddress,
            nameof(ActivationDetailsRequest.emailAddress),
            ActivationDetailsRequest.MaxEmailAddressLength);

        if (string.IsNullOrWhiteSpace(payload.code))
        {
            errors.Add(ApiResponses.ValidationError(nameof(ActivationDetailsRequest.code), "code is required."));
        }
        else if (payload.code.Length > ActivationDetailsRequest.MaxCodeLength)
        {
            errors.Add(ApiResponses.ValidationError(
                nameof(ActivationDetailsRequest.code),
                $"code must be no longer than {ActivationDetailsRequest.MaxCodeLength} characters."));
        }

        return errors.Count == 0
            ? null
            : ApiResponses.InvalidPayload(EmptyDetails(Pass.INVALID), errors);
    }

    private ApiOutcome<ActivationUnSubscribeResponse>? ValidateUnSubscribeRequest(ActivationUnSubscribeRequest? payload)
    {
        if (payload == null)
        {
            return ApiResponses.InvalidPayload(
                new ActivationUnSubscribeResponse(Pass.INVALID),
                string.Empty,
                RequestBodyRequiredMessage);
        }

        payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;

        var errors = new List<ApiValidationError>();
        AddEmailValidation(
            errors,
            payload.emailAddress,
            nameof(ActivationUnSubscribeRequest.emailAddress),
            ActivationUnSubscribeRequest.MaxEmailAddressLength);

        return errors.Count == 0
            ? null
            : ApiResponses.InvalidPayload(new ActivationUnSubscribeResponse(Pass.INVALID), errors);
    }

    private void AddEmailValidation(List<ApiValidationError> errors, string? emailAddress, string fieldName, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(emailAddress))
        {
            errors.Add(ApiResponses.ValidationError(fieldName, "emailAddress is required."));
        }
        else if (emailAddress.Length > maxLength)
        {
            errors.Add(ApiResponses.ValidationError(fieldName, $"emailAddress must be no longer than {maxLength} characters."));
        }
        else if (!_emailValidator.IsValid(emailAddress))
        {
            errors.Add(ApiResponses.ValidationError(fieldName, "emailAddress must be a valid email address."));
        }
    }

    private bool TryGetAuthenticatedSession(out ActiveSession activeSession)
    {
        if (HttpContext.Items[AuthContextItems.ActiveSession] is ActiveSession session)
        {
            activeSession = session;
            return true;
        }

        activeSession = default!;
        return false;
    }

    private ActionResult<ApiResponse<T>> ToActionResult<T>(ApiOutcome<T> outcome)
    {
        return ApiResponses.FromOutcome(this, outcome);
    }

    private async Task<AuthenticatedMutationIdempotencyBeginResult> BeginAuthenticatedMutationIdempotency(
        ActiveSession activeSession,
        string route,
        bool requireKey = false)
    {
        string? key = Request.Headers.TryGetValue(AuthenticatedMutationIdempotencyConstants.HeaderName, out var values)
            ? values.FirstOrDefault()
            : null;

        return await _authenticatedMutationIdempotencyService.BeginAsync(
            new AuthenticatedMutationIdempotencyRequest(
                activeSession.accountId,
                HttpMethods.Post,
                route,
                key,
                requireKey),
            HttpContext.RequestAborted);
    }

    private async Task CompleteAuthenticatedMutationIdempotency(
        AuthenticatedMutationIdempotencyBeginResult idempotency,
        int statusCode,
        string code)
    {
        if (idempotency.Reservation is null)
        {
            return;
        }

        await _authenticatedMutationIdempotencyService.CompleteAsync(
            idempotency.Reservation,
            statusCode,
            code,
            HttpContext.RequestAborted);
    }

    private static ApiOutcome<T>? IdempotencyBlockingOutcome<T>(
        AuthenticatedMutationIdempotencyBeginResult idempotency,
        T failureBody)
    {
        return idempotency.Status switch
        {
            AuthenticatedMutationIdempotencyStatus.MissingRequiredKey => new ApiOutcome<T>(
                failureBody,
                StatusCodes.Status428PreconditionRequired,
                AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode),
            AuthenticatedMutationIdempotencyStatus.InvalidKey => ApiResponses.InvalidPayload(
                failureBody,
                AuthenticatedMutationIdempotencyConstants.HeaderName,
                "Idempotency-Key must be 16 to 128 characters and contain only letters, digits, underscore, dash, period, or colon."),
            AuthenticatedMutationIdempotencyStatus.StoreUnavailable => new ApiOutcome<T>(
                failureBody,
                StatusCodes.Status503ServiceUnavailable,
                AuthenticatedMutationIdempotencyConstants.StoreUnavailableCode),
            AuthenticatedMutationIdempotencyStatus.ReplayInProgress => new ApiOutcome<T>(
                failureBody,
                StatusCodes.Status409Conflict,
                AuthenticatedMutationIdempotencyConstants.ReplayInProgressCode),
            _ => null
        };
    }

    private static ApiOutcome<T>? IdempotencyReplayOutcome<T>(
        AuthenticatedMutationIdempotencyBeginResult idempotency,
        Func<int, string, T> bodyFactory)
    {
        if (idempotency.Status != AuthenticatedMutationIdempotencyStatus.ReplayCompleted || idempotency.StoredResult is null)
        {
            return null;
        }

        return new ApiOutcome<T>(
            bodyFactory(idempotency.StoredResult.StatusCode, idempotency.StoredResult.Code),
            idempotency.StoredResult.StatusCode,
            idempotency.StoredResult.Code);
    }

    private static ActivationDetailsResponse EmptyDetails(Pass result)
    {
        return new ActivationDetailsResponse(result, string.Empty, 0, 0);
    }

    private static Pass ActivationPass(string code)
    {
        return code switch
        {
            ActivationService.NotFoundCode => Pass.NOT_FOUND,
            ActivationService.SecurityStampMismatchCode => Pass.UNAUTHORIZED,
            ActivationService.InvalidCode or ActivationService.InvalidTermCode or ActivationService.InvalidRecycleCode or
                ActivationService.CodeMismatchCode or ActivationService.EmailMismatchCode => Pass.INVALID,
            ActivationService.ExpiredCode => Pass.INVALID,
            ActivationService.ConflictCode => Pass.FAILED,
            AbuseReasonCodes.ActivationVerifyAttemptsExceeded or AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout => Pass.FAILED,
            ActivationService.FailedCode or ActivationService.EmailDeliveryFailedCode or ActivationService.CleanupFailedCode => Pass.FAILED,
            _ => Pass.FAILED
        };
    }

    private static int ActivationStatusCode(string code, int successStatusCode)
    {
        return code switch
        {
            ActivationService.CreatedCode or ActivationService.VerifiedCode or ActivationService.DisabledCode => successStatusCode,
            ActivationService.SecurityStampMismatchCode => StatusCodes.Status401Unauthorized,
            ActivationService.EmailMismatchCode or ActivationService.CodeMismatchCode or ActivationService.InvalidCode or
                ActivationService.InvalidTermCode or ActivationService.InvalidRecycleCode => StatusCodes.Status400BadRequest,
            ActivationService.NotFoundCode => StatusCodes.Status404NotFound,
            ActivationService.ExpiredCode => StatusCodes.Status410Gone,
            ActivationService.ConflictCode => StatusCodes.Status409Conflict,
            AbuseReasonCodes.ActivationVerifyAttemptsExceeded => StatusCodes.Status429TooManyRequests,
            AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout => StatusCodes.Status503ServiceUnavailable,
            ActivationService.EmailDeliveryFailedCode or ActivationService.CleanupFailedCode or ActivationService.FailedCode => StatusCodes.Status500InternalServerError,
            _ => StatusCodes.Status500InternalServerError
        };
    }
}
