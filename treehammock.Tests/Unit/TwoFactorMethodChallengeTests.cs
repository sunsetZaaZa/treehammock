using Microsoft.AspNetCore.Http;
using NSubstitute;
using Newtonsoft.Json;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class TwoFactorMethodChallengeTests
{
    [Fact]
    public async Task TwoFactorMethod_rejects_negative_destination_as_validation_failure_without_loading_session()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL, destination: -1));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldContain(error => error.field == nameof(LayeredAuthenticateMethodsRequest.destination));
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_unsupported_method_as_validation_failure_without_loading_session()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest((TwoFactorAuthMethod)999));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldContain(error => error.field == nameof(LayeredAuthenticateMethodsRequest.method));
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_request_without_pre_auth_token()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var request = new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.SMS_KEY);

        var actionResult = await controller.TwoFactorMethod(request);

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeFalse();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_unknown_pending_session()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(null));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeFalse();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).GetSession(hash);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_valid_active_token_without_pending_pre_auth_session()
    {
        var harness = new AccountControllerHarness();
        const string activeToken = "valid-active-token";
        string hash = AccessTokenHashUtility.Hash(activeToken);
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(null));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = activeToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeFalse();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).GetSession(hash);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_pending_session_when_jwt_validation_fails()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.SMS_KEY], phoneNumbers: ["5555550101"], phoneCountryCodes: ["1"]);
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.JwtUtility.ValidateAccessToken(preAuthToken, session.preAuthRefreshToken, Arg.Any<Instant>(), session.expiration, JsonWebTokenPurpose.PreAuthTwoFactor)
            .Returns(Task.FromResult((IntraMessage.TOKEN_FAILED_VALIDATION, (string?)null)));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.SMS_KEY));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeFalse();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorMethod_preserves_expired_pending_session_reason()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        session.expiration = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1));
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }


    [Fact]
    public async Task TwoFactorMethod_preserves_cutoff_expired_pending_session_reason()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildPendingSession(
            methods: [TwoFactorAuthMethod.EMAIL],
            emailAddresses: ["reader@example.com"],
            cutOff: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_500_when_expired_pending_session_revoke_fails()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        session.expiration = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1));
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SESSION_REVOKE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_401_for_expired_session_before_method_availability_validation()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        session.expiration = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1));
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.SMS_KEY));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
        envelope.errors.ShouldBeNull();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_method_that_is_not_available_in_pending_session_as_validation_failure()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        PrepareValidPendingSession(harness, preAuthToken, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.SMS_KEY));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldContain(error => error.field == nameof(LayeredAuthenticateMethodsRequest.method));
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorMethod_sms_generates_sends_and_stores_hashed_one_time_code()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.SMS_KEY], phoneNumbers: ["5555550101"], phoneCountryCodes: ["1"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        string? sentCode = null;
        TwoFactorSession? storedSession = null;
        harness.TwoFactorService.SMS("+15555550101", Arg.Do<string>(code => sentCode = code)).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Do<TwoFactorSession>(value => storedSession = value), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.SMS_KEY));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.TWOFACTOR_WAITING_SMS_KEY);
        response.method.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        response.chosenDestination.ShouldBe((short)0);
        sentCode.ShouldNotBeNull();
        sentCode!.Length.ShouldBe(6);
        storedSession.ShouldNotBeNull();
        storedSession!.challengedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        storedSession.chosenDestination.ShouldBe((short)0);
        storedSession.challengeExpiration.ShouldNotBeNull();
        storedSession.challengeCodeHash.ShouldBe(TwoFactorChallengeCodeUtility.Hash(sentCode, "test-two-factor-pepper"));
        storedSession.challengeCodeHash.ShouldNotBe(sentCode);
        storedSession.intraCodeKey.ShouldBe(storedSession.challengeCodeHash);
        storedSession.challengeProviderTransactionId.ShouldBeNull();
    }

    [Fact]
    public async Task TwoFactorMethod_email_generates_sends_and_stores_hashed_one_time_code()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        string? sentCode = null;
        TwoFactorSession? storedSession = null;
        harness.TwoFactorService.Email("reader@example.com", Arg.Do<string>(code => sentCode = code)).Returns(Task.FromResult(true));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Do<TwoFactorSession>(value => storedSession = value), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.TWOFACTOR_WAITING_INTRA_EMAIL);
        response.method.ShouldBe(TwoFactorAuthMethod.EMAIL);
        sentCode.ShouldNotBeNull();
        storedSession.ShouldNotBeNull();
        storedSession!.challengedMethod.ShouldBe(TwoFactorAuthMethod.EMAIL);
        storedSession.challengeCodeHash.ShouldBe(TwoFactorChallengeCodeUtility.Hash(sentCode!, "test-two-factor-pepper"));
        storedSession.challengeCodeHash.ShouldNotBe(sentCode);
    }

    [Fact]
    public async Task TwoFactorMethod_prepares_authenticator_app_no_delivery_challenge()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(
            methods: [TwoFactorAuthMethod.AUTHENTICATOR_APP],
            userAuthIds: ["authenticator-app-user-1"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        TwoFactorSession? storedSession = null;
        harness.TwoFactorSessionService.SetSession(hash, Arg.Do<TwoFactorSession>(value => storedSession = value), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.AUTHENTICATOR_APP));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeTrue();
        response.result.ShouldBe(HttpMessage.TWOFACTOR_WAITING_AUTHENTICATOR_APP);
        response.method.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        response.chosenDestination.ShouldBe((short)0);
        storedSession.ShouldNotBeNull();
        storedSession!.challengedMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        storedSession.challengeCodeHash.ShouldBeNull();
        storedSession.intraCodeKey.ShouldBeNull();
        await harness.AccountRepo.Received(1).RecordTwoFactorChallengeIssued(
            Arg.Is<Guid>(value => value == session.accountId),
            Arg.Is<Guid>(value => value == session.accountSecurityStamp),
            Arg.Any<string?>()!,
            Arg.Is<TwoFactorAuthMethod>(value => value == TwoFactorAuthMethod.AUTHENTICATOR_APP),
            Arg.Is<short>(value => value == 0),
            Arg.Is<string?>(value => value == null),
            Arg.Is<string?>(value => value == null),
            Arg.Any<Instant>(),
            Arg.Any<Instant>(),
            Arg.Any<short>(),
            Arg.Any<Instant>(),
                Arg.Any<TwoFactorAuthConfiguration?>(),
                Arg.Any<TwoFactorSessionState?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<TwoFactorAuthMethod?>(),
                Arg.Any<Instant?>());
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_authenticator_app_nonzero_destination_before_loading_pending_session()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.AUTHENTICATOR_APP, destination: 1));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("VALIDATION_FAILED");
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.Single().field.ShouldBe(nameof(LayeredAuthenticateMethodsRequest.destination));
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_unavailable_destination_index()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        PrepareValidPendingSession(harness, preAuthToken, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL, destination: 3));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_INVALID_DESTINATION");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_500_when_email_provider_cannot_send_challenge()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>()).Returns(Task.FromResult(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PROVIDER_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).CancelTwoFactorChallengeIssued(
            session.accountId,
            session.accountSecurityStamp,
            Arg.Is(hash),
            TwoFactorAuthMethod.EMAIL,
            0,
            Arg.Any<string?>(),
            Arg.Is<string?>(value => value == null),
            Arg.Any<Instant>());
        await harness.TwoFactorSessionService.Received(1).SetSession(hash, Arg.Is<TwoFactorSession>(value =>
            value.challengedMethod == null &&
            value.challengeCodeHash == null &&
            value.challengeExpiration == null &&
            value.nextChallengeAllowedAt == null), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TwoFactorMethod_returns_500_when_sms_provider_cannot_send_challenge()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.SMS_KEY], phoneNumbers: ["5555550101"], phoneCountryCodes: ["1"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.SMS("+15555550101", Arg.Any<string>()).Returns(Task.FromResult<bool?>(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.SMS_KEY));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PROVIDER_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).CancelTwoFactorChallengeIssued(
            session.accountId,
            session.accountSecurityStamp,
            Arg.Is(hash),
            TwoFactorAuthMethod.SMS_KEY,
            0,
            Arg.Any<string?>(),
            Arg.Is<string?>(value => value == null),
            Arg.Any<Instant>());
        await harness.TwoFactorSessionService.Received(1).SetSession(hash, Arg.Is<TwoFactorSession>(value =>
            value.challengedMethod == null &&
            value.challengeCodeHash == null &&
            value.challengeExpiration == null &&
            value.nextChallengeAllowedAt == null), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TwoFactorMethod_returns_cleanup_failure_when_provider_failure_challenge_cleanup_fails()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>()).Returns(Task.FromResult(false));
        harness.AccountRepo.CancelTwoFactorChallengeIssued(
                session.accountId,
                session.accountSecurityStamp,
                Arg.Is(hash),
                Arg.Any<TwoFactorAuthMethod>(),
                Arg.Any<short>(),
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(false, "TWO_FACTOR_CHALLENGE_MISMATCH", 0, 1, null, null)));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_CHALLENGE_CLEANUP_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).CancelTwoFactorChallengeIssued(
            session.accountId,
            session.accountSecurityStamp,
            Arg.Is(hash),
            TwoFactorAuthMethod.EMAIL,
            0,
            Arg.Any<string?>(),
            Arg.Is<string?>(value => value == null),
            Arg.Any<Instant>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_resend_during_cooldown()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        session.nextChallengeAllowedAt = SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromSeconds(20));
        PrepareValidPendingSession(harness, preAuthToken, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status400BadRequest);
        response.outcome.ShouldBeFalse();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_CODE_TIMEOUT);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_revokes_pending_session_after_too_many_resends()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        session.challengeResends = (short)harness.LoginSettings.TwoAuthRetryLimit;
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status401Unauthorized);
        response.outcome.ShouldBeFalse();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_500_when_resend_limit_revoke_fails()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        session.challengeResends = (short)harness.LoginSettings.TwoAuthRetryLimit;
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SESSION_REVOKE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_revokes_pending_session_when_challenge_cache_write_fails_after_provider_send()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>()).Returns(Task.FromResult(true));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(false));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_CHALLENGE_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorService.Received(1).Email("reader@example.com", Arg.Any<string>());
        await harness.TwoFactorSessionService.Received(1).SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_500_when_challenge_cache_write_and_cleanup_revoke_fail()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>()).Returns(Task.FromResult(true));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(false));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SESSION_REVOKE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorService.Received(1).Email("reader@example.com", Arg.Any<string>());
        await harness.TwoFactorSessionService.Received(1).SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
    }


    [Fact]
    public async Task TwoFactorMethod_returns_provider_failure_when_email_provider_throws()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>())
            .Returns(_ => Task.FromException<bool>(new InvalidOperationException("smtp failed")));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PROVIDER_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).CancelTwoFactorChallengeIssued(
            session.accountId,
            session.accountSecurityStamp,
            Arg.Is(hash),
            TwoFactorAuthMethod.EMAIL,
            0,
            Arg.Any<string?>(),
            Arg.Is<string?>(value => value == null),
            Arg.Any<Instant>());
        await harness.TwoFactorSessionService.Received(1).SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TwoFactorMethod_returns_provider_failure_when_sms_provider_throws()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.SMS_KEY], phoneNumbers: ["5555550101"], phoneCountryCodes: ["1"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.SMS("+15555550101", Arg.Any<string>())
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("sms failed")));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.SMS_KEY));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PROVIDER_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).CancelTwoFactorChallengeIssued(
            session.accountId,
            session.accountSecurityStamp,
            Arg.Is(hash),
            TwoFactorAuthMethod.SMS_KEY,
            0,
            Arg.Any<string?>(),
            Arg.Is<string?>(value => value == null),
            Arg.Any<Instant>());
        await harness.TwoFactorSessionService.Received(1).SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TwoFactorMethod_rejects_pending_session_invalidated_by_account_security_stamp_bump()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.AccountRepo.IsPendingTwoFactorSessionCurrent(session.accountId, hash, session.accountSecurityStamp).Returns(Task.FromResult<bool?>(false));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PENDING_SESSION_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).IsPendingTwoFactorSessionCurrent(session.accountId, hash, session.accountSecurityStamp);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_revoke_failure_when_stale_pending_session_cleanup_fails()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.AccountRepo.IsPendingTwoFactorSessionCurrent(session.accountId, hash, session.accountSecurityStamp).Returns(Task.FromResult<bool?>(false));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SESSION_REVOKE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).IsPendingTwoFactorSessionCurrent(session.accountId, hash, session.accountSecurityStamp);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorMethod_revokes_malformed_pending_session_payload_as_stale_cache()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.TwoFactorSessionService.GetSession(hash)
            .Returns(_ => Task.FromException<TwoFactorSession?>(new StalePendingTwoFactorCachePayloadException("missing accountSecurityStamp")));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PENDING_SESSION_MISMATCH");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).GetSession(hash);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().IsPendingTwoFactorSessionCurrent(default, default!, default);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_revoke_failure_when_malformed_pending_session_cleanup_fails()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.TwoFactorSessionService.GetSession(hash)
            .Returns(_ => Task.FromException<TwoFactorSession?>(new StalePendingTwoFactorCachePayloadException("missing accountSecurityStamp")));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SESSION_REVOKE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).GetSession(hash);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.JwtUtility.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_persistence_failure_when_pending_session_read_throws()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.TwoFactorSessionService.GetSession(hash)
            .Returns(_ => Task.FromException<TwoFactorSession?>(new InvalidOperationException("redis read failed")));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_CHALLENGE_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).GetSession(hash);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_returns_revoke_failure_when_expired_pending_session_revoke_throws()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        session.expiration = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1));
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.TwoFactorSessionService.RevokeSession(hash)
            .Returns(_ => Task.FromException<bool>(new InvalidOperationException("redis revoke failed")));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SESSION_REVOKE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_revokes_pending_session_when_challenge_cache_write_throws_after_provider_send()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>()).Returns(Task.FromResult(true));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>())
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("redis write failed")));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_CHALLENGE_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.outcome.ShouldBeFalse();
        envelope.data.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.TwoFactorService.Received(1).Email("reader@example.com", Arg.Any<string>());
        await harness.TwoFactorSessionService.Received(1).SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
    }


    [Fact]
    public async Task TwoFactorMethod_uses_durable_resend_limit_from_database()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        harness.AccountRepo.RecordTwoFactorChallengeIssued(
                Arg.Is<Guid>(value => value == session.accountId),
                Arg.Is<Guid>(value => value == session.accountSecurityStamp),
                Arg.Any<string?>()!,
                Arg.Any<TwoFactorAuthMethod>(),
                Arg.Any<short>(),
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Any<short>(),
                Arg.Any<Instant>(),
                Arg.Any<TwoFactorAuthConfiguration?>(),
                Arg.Any<TwoFactorSessionState?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<TwoFactorAuthMethod?>(),
                Arg.Any<Instant?>())
            .Returns(Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(false, "TWO_FACTOR_CHALLENGE_RESEND_LIMIT", 0, (short)harness.LoginSettings.TwoAuthRetryLimit, null, null)));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status401Unauthorized);
        response.outcome.ShouldBeFalse();
        response.result.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED);
        await harness.AccountRepo.Received(1).RecordTwoFactorChallengeIssued(
            Arg.Is<Guid>(value => value == session.accountId),
            Arg.Is<Guid>(value => value == session.accountSecurityStamp),
            Arg.Any<string?>()!,
            Arg.Is<TwoFactorAuthMethod>(value => value == TwoFactorAuthMethod.EMAIL),
            Arg.Is<short>(value => value == 0),
            Arg.Any<string?>(),
            Arg.Any<string?>(),
            Arg.Any<Instant>(),
            Arg.Any<Instant>(),
            Arg.Any<short>(),
            Arg.Any<Instant>(),
                Arg.Any<TwoFactorAuthConfiguration?>(),
                Arg.Any<TwoFactorSessionState?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<TwoFactorAuthMethod?>(),
                Arg.Any<Instant?>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(hash);
        _ = harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!);
    }

    [Fact]
    public async Task TwoFactorMethod_caps_email_challenge_expiration_and_cache_ttl_at_pending_session_ttl()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        var session = BuildPendingSession(methods: [TwoFactorAuthMethod.EMAIL], emailAddresses: ["reader@example.com"]);
        string hash = PrepareValidPendingSession(harness, preAuthToken, session);
        Instant? recordedChallengeExpiration = null;
        TimeSpan? cacheTtl = null;
        harness.TwoFactorService.Email("reader@example.com", Arg.Any<string>()).Returns(Task.FromResult(true));
        harness.AccountRepo.RecordTwoFactorChallengeIssued(
                Arg.Is<Guid>(value => value == session.accountId),
                Arg.Is<Guid>(value => value == session.accountSecurityStamp),
                Arg.Any<string?>()!,
                Arg.Any<TwoFactorAuthMethod>(),
                Arg.Any<short>(),
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Any<short>(),
                Arg.Any<Instant>(),
                Arg.Any<TwoFactorAuthConfiguration?>(),
                Arg.Any<TwoFactorSessionState?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<TwoFactorAuthMethod?>(),
                Arg.Any<Instant?>())
            .Returns(callInfo =>
            {
                recordedChallengeExpiration = callInfo.ArgAt<Instant>(7);
                var nextAllowed = callInfo.ArgAt<Instant>(8);
                return Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(true, "TWO_FACTOR_CHALLENGE_ISSUED", 0, (short)(session.challengeResends + 1), recordedChallengeExpiration, nextAllowed));
            });
        harness.TwoFactorSessionService.SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Do<TimeSpan>(ttl => cacheTtl = ttl))
            .Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorMethod(new LayeredAuthenticateMethodsRequest(TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.outcome.ShouldBeTrue();
        recordedChallengeExpiration.ShouldNotBeNull();
        recordedChallengeExpiration!.Value.ShouldBeLessThanOrEqualTo(session.expiration);
        cacheTtl.ShouldNotBeNull();
        cacheTtl!.Value.ShouldBeLessThanOrEqualTo(TimeSpan.FromMinutes(2));
        cacheTtl.Value.ShouldBeGreaterThan(TimeSpan.Zero);
    }

    private static string PrepareValidPendingSession(AccountControllerHarness harness, string preAuthToken, TwoFactorSession session)
    {
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.JwtUtility.ValidateAccessToken(preAuthToken, session.preAuthRefreshToken, Arg.Any<Instant>(), session.expiration, JsonWebTokenPurpose.PreAuthTwoFactor)
            .Returns(Task.FromResult<(IntraMessage, string?)>((IntraMessage.TOKEN_PASSED_VALIDATION, session.webKey)));
        harness.AccountRepo.IsPendingTwoFactorSessionCurrent(session.accountId, hash, session.accountSecurityStamp).Returns(Task.FromResult<bool?>(true));
        harness.AccountRepo.RecordTwoFactorChallengeIssued(
                Arg.Is<Guid>(value => value == session.accountId),
                Arg.Is<Guid>(value => value == session.accountSecurityStamp),
                Arg.Any<string?>()!,
                Arg.Any<TwoFactorAuthMethod>(),
                Arg.Any<short>(),
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Any<short>(),
                Arg.Any<Instant>(),
                Arg.Any<TwoFactorAuthConfiguration?>(),
                Arg.Any<TwoFactorSessionState?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<IReadOnlyCollection<TwoFactorAuthMethod>?>(),
                Arg.Any<TwoFactorAuthMethod?>(),
                Arg.Any<Instant?>())
            .Returns(callInfo =>
            {
                var challengeExpiration = callInfo.ArgAt<Instant>(7);
                var nextAllowed = callInfo.ArgAt<Instant>(8);
                return Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(true, "TWO_FACTOR_CHALLENGE_ISSUED", 0, (short)(session.challengeResends + 1), challengeExpiration, nextAllowed));
            });
        harness.AccountRepo.CancelTwoFactorChallengeIssued(
                session.accountId,
                session.accountSecurityStamp,
                Arg.Is(hash),
                Arg.Any<TwoFactorAuthMethod>(),
                Arg.Any<short>(),
                Arg.Any<string?>(),
                Arg.Any<string?>(),
                Arg.Any<Instant>())
            .Returns(_ => Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(true, "TWO_FACTOR_CHALLENGE_CANCELLED", 0, (short)Math.Max(0, session.challengeResends - 1), null, null)));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>())
            .Returns(Task.FromResult<bool?>(true));
        return hash;
    }

    private static TwoFactorSession BuildPendingSession(
        List<TwoFactorAuthMethod> methods,
        List<string>? userAuthIds = null,
        List<string>? phoneNumbers = null,
        List<string>? phoneCountryCodes = null,
        List<string>? emailAddresses = null,
        Instant? cutOff = null)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        return new TwoFactorSession(
            Guid.NewGuid(),
            "web-key",
            Enumerable.Repeat((byte)7, 64).ToArray(),
            methods,
            userAuthIds,
            phoneNumbers,
            phoneCountryCodes,
            emailAddresses,
            null,
            null,
            0,
            0,
            0,
            now,
            now.Plus(Duration.FromMinutes(2)),
            FeatureSet.basic,
            cutOff,
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-000000000002"));
    }
}
