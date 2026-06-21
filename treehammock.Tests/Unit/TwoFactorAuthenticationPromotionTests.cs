using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Abuse;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Repos;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class TwoFactorAuthenticationPromotionTests
{
    [Fact]
    public async Task TwoFactorAuthenticate_rejects_empty_code_key_as_validation_failure_without_loading_session()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest(string.Empty, TwoFactorAuthMethod.SMS_KEY));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldContain(error => error.field == nameof(LayeredAuthenticateRequest.codeKey));
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_accepts_authenticator_app_method_shape_but_requires_pending_session()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.AUTHENTICATOR_APP));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().GetSession(default!);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorRotationLogin(default, default!, default, default!, default!, default!);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_rejects_request_without_pre_auth_token()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult);
        response.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        response.accessToken.ShouldBeNull();
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorRotationLogin(default, default!, default, default!, default!, default!);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_rejects_and_revokes_expired_pending_two_factor_session()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        session.expiration = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromSeconds(1));
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(preAuthHash);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorRotationLogin(default, default!, default, default!, default!, default!);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_promotes_new_login_atomically_in_database_before_cache_write()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_NEW_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        response.accessToken.ShouldBe(finalToken);
        await harness.AccountRepo.Received(1).PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Is<Session>(record => record.accountId == session.accountId));
        await harness.ActiveUserCacheService.Received(1).SetSession(finalHash, Arg.Is<ActiveSession>(record => record.accountId == session.accountId), Arg.Any<TimeSpan>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(preAuthHash);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SuccessfulTwoFactorAuth(default, default!, default);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_cache_write_failure_after_new_promotion_still_returns_token_without_db_rollback()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_NEW_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(false));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        response.accessToken.ShouldBe(finalToken);
        await harness.ActiveUserCacheService.Received(1).SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        await harness.SessionRepo.DidNotReceive().ExpireSession(finalHash, null);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(preAuthHash);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SuccessfulTwoFactorAuth(default, default!, default);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_promotes_rotation_atomically_in_database_before_cache_write()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        const string priorActiveHash = "prior-active-hash";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456", priorActiveAccessTokenHash: priorActiveHash);
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorRotationLogin(session.accountId, preAuthHash, session.accountSecurityStamp, priorActiveHash, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_ROTATION_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        harness.ActiveUserCacheService.RevokeSession(priorActiveHash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        response.accessToken.ShouldBe(finalToken);
        await harness.AccountRepo.Received(1).PromoteTwoFactorRotationLogin(session.accountId, preAuthHash, session.accountSecurityStamp, priorActiveHash, finalHash, Arg.Is<Session>(record => record.accountId == session.accountId));
        await harness.ActiveUserCacheService.Received(1).SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(priorActiveHash);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().RotateActiveSession(default, default!, default!, default!);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SuccessfulTwoFactorAuth(default, default!, default);
    }


    [Fact]
    public async Task TwoFactorAuthenticate_cache_write_failure_after_rotation_promotion_still_returns_token_without_db_rollback()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        const string priorActiveHash = "prior-active-hash";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456", priorActiveAccessTokenHash: priorActiveHash);
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorRotationLogin(session.accountId, preAuthHash, session.accountSecurityStamp, priorActiveHash, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_ROTATION_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(false));
        harness.ActiveUserCacheService.RevokeSession(priorActiveHash).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        response.accessToken.ShouldBe(finalToken);
        await harness.ActiveUserCacheService.Received(1).SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        await harness.ActiveUserCacheService.Received(1).RevokeSession(priorActiveHash);
        await harness.SessionRepo.DidNotReceive().ExpireSession(finalHash, null);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(preAuthHash);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_failed_challenge_attempt_increments_abuse_counter_before_durable_failure()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.AccountRepo.RecordTwoFactorChallengeFailure(session.accountId, session.accountSecurityStamp, preAuthHash, Arg.Any<short>(), Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(true, "TWO_FACTOR_CHALLENGE_FAILED", 1, 1, session.challengeExpiration, session.nextChallengeAllowedAt)));
        harness.TwoFactorSessionService.SetSession(preAuthHash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("000000", TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status401Unauthorized);
        response.result.ShouldBe(TwoFactorAuthOutcome.INCORRECT);
        await harness.AbuseCounterStore.Received(1).IncrementAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.TwoFactorChallenge &&
                key.Dimension == AbuseCounterDimension.Session &&
                key.SafeId != preAuthHash &&
                !key.SafeId.Contains("000000", StringComparison.Ordinal)),
            Arg.Is<AbuseCounterLimit>(limit => limit.MaxAttempts == harness.AbuseControlSettings.TwoFactor.MaxAttemptsPerChallenge),
            Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).RecordTwoFactorChallengeFailure(session.accountId, session.accountSecurityStamp, preAuthHash, Arg.Any<short>(), Arg.Any<Instant>());
        await harness.AbuseCounterStore.DidNotReceiveWithAnyArgs().ResetAsync(default!, default);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_denies_exhausted_challenge_attempts_without_checking_submitted_proof()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        TimeSpan retryAfter = TimeSpan.FromMinutes(15);
        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: harness.AbuseControlSettings.TwoFactor.MaxAttemptsPerChallenge + 1,
                Limit: harness.AbuseControlSettings.TwoFactor.MaxAttemptsPerChallenge,
                Window: TimeSpan.FromSeconds(harness.AbuseControlSettings.TwoFactor.ChallengeAttemptWindowSeconds),
                RetryAfter: retryAfter,
                ReasonCode: AbuseReasonCodes.CounterLimitExceeded)));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.TwoFactorAttemptsExceeded);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        harness.HttpContext.Response.Headers["Retry-After"].ToString().ShouldBe("900");
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().RecordTwoFactorChallengeFailure(default, default, default!, default, default);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
        await harness.AbuseCounterStore.DidNotReceiveWithAnyArgs().ResetAsync(default!, default);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_fails_closed_when_abuse_counter_store_is_unavailable_without_checking_submitted_proof()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 0,
                Limit: harness.AbuseControlSettings.TwoFactor.MaxAttemptsPerChallenge,
                Window: TimeSpan.FromSeconds(harness.AbuseControlSettings.TwoFactor.ChallengeAttemptWindowSeconds),
                RetryAfter: null,
                ReasonCode: AbuseReasonCodes.CounterStoreUnavailable)));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status503ServiceUnavailable);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().RecordTwoFactorChallengeFailure(default, default, default!, default, default);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorRotationLogin(default, default!, default, default!, default!, default!);
        await harness.AbuseCounterStore.DidNotReceiveWithAnyArgs().ResetAsync(default!, default);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_resets_challenge_attempt_counter_on_success()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_NEW_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.TwoFactorChallenge && key.Dimension == AbuseCounterDimension.Session),
            Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task TwoFactorAuthenticate_promotes_authenticator_app_login_after_backend_local_totp_verification()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        var verifier = Substitute.For<IAuthenticatorAppLoginVerifier>();
        verifier.VerifyForLoginAsync(session.accountId, "123456", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatorAppLoginVerificationResult.Success()));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_NEW_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.RequestServices = new ServiceCollection()
            .AddSingleton(verifier)
            .BuildServiceProvider();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.AUTHENTICATOR_APP));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        response.accessToken.ShouldBe(finalToken);
        await verifier.Received(1).VerifyForLoginAsync(session.accountId, "123456", Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>());
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.TwoFactorChallenge && key.Dimension == AbuseCounterDimension.Session),
            Arg.Any<CancellationToken>());
        await harness.TwoFactorService.DidNotReceiveWithAnyArgs().Email(default!, default!, default);
        await harness.TwoFactorService.DidNotReceiveWithAnyArgs().SMS(default!, default!, default);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_records_authenticator_app_failure_without_promoting_session()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        var verifier = Substitute.For<IAuthenticatorAppLoginVerifier>();
        verifier.VerifyForLoginAsync(session.accountId, "000000", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatorAppLoginVerificationResult.Failed(AuthenticatorAppLoginVerifier.IncorrectCode)));
        harness.AccountRepo.RecordTwoFactorChallengeFailure(session.accountId, session.accountSecurityStamp, preAuthHash, Arg.Any<short>(), Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(true, "TWO_FACTOR_CHALLENGE_FAILURE_RECORDED", 1, 1, session.challengeExpiration, session.nextChallengeAllowedAt)));
        harness.TwoFactorSessionService.SetSession(preAuthHash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.RequestServices = new ServiceCollection()
            .AddSingleton(verifier)
            .BuildServiceProvider();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("000000", TwoFactorAuthMethod.AUTHENTICATOR_APP));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status401Unauthorized);
        response.result.ShouldBe(TwoFactorAuthOutcome.INCORRECT);
        await verifier.Received(1).VerifyForLoginAsync(session.accountId, "000000", Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).RecordTwoFactorChallengeFailure(session.accountId, session.accountSecurityStamp, preAuthHash, Arg.Any<short>(), Arg.Any<Instant>());
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorRotationLogin(default, default!, default, default!, default!, default!);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_accepts_sms_first_for_sms_and_authenticator_without_promoting()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildSelectedComboSession(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.AccountRepo.RecordTwoFactorChallengeIssued(
                session.accountId,
                session.accountSecurityStamp,
                Arg.Is<string>(value => value == preAuthHash),
                TwoFactorAuthMethod.AUTHENTICATOR_APP,
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
                Arg.Any<Instant?>())
            .Returns(call => Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(
                true,
                "TWO_FACTOR_CHALLENGE_ISSUED",
                0,
                session.challengeResends,
                call.ArgAt<Instant>(7),
                call.ArgAt<Instant>(8))));
        harness.TwoFactorSessionService.SetSession(preAuthHash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.SMS_KEY));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        envelope.data.accessToken.ShouldBeNull();
        envelope.data.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        envelope.data.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        envelope.data.completedTwoFactorAuthMethods.ShouldNotBeNull();
        envelope.data.completedTwoFactorAuthMethods!.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
        envelope.data.remainingTwoFactorAuthMethods.ShouldNotBeNull();
        envelope.data.remainingTwoFactorAuthMethods!.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
        await harness.TwoFactorSessionService.Received(1).SetSession(
            preAuthHash,
            Arg.Is<TwoFactorSession>(stored =>
                stored.completedMethods.SequenceEqual(new[] { TwoFactorAuthMethod.SMS_KEY }) &&
                stored.currentExpectedMethod == TwoFactorAuthMethod.AUTHENTICATOR_APP &&
                stored.challengedMethod == TwoFactorAuthMethod.AUTHENTICATOR_APP &&
                stored.state == TwoFactorSessionState.AwaitingAuthenticatorCode),
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task TwoFactorAuthenticate_rejects_authenticator_before_sms_for_sms_and_authenticator()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildSelectedComboSession(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.AUTHENTICATOR_APP));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.code.ShouldBe("TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        envelope.data.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().RecordTwoFactorChallengeFailure(default, default, default!, default, default);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_promotes_after_authenticator_second_for_sms_and_authenticator()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildSelectedComboSession(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, code: null);
        session.completedMethods = [TwoFactorAuthMethod.SMS_KEY];
        session.currentExpectedMethod = TwoFactorAuthMethod.AUTHENTICATOR_APP;
        session.challengedMethod = TwoFactorAuthMethod.AUTHENTICATOR_APP;
        session.state = TwoFactorSessionState.AwaitingAuthenticatorCode;
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        var verifier = Substitute.For<IAuthenticatorAppLoginVerifier>();
        verifier.VerifyForLoginAsync(session.accountId, "654321", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatorAppLoginVerificationResult.Success()));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_NEW_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.RequestServices = new ServiceCollection()
            .AddSingleton(verifier)
            .BuildServiceProvider();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("654321", TwoFactorAuthMethod.AUTHENTICATOR_APP));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        response.accessToken.ShouldBe(finalToken);
        await verifier.Received(1).VerifyForLoginAsync(session.accountId, "654321", Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await harness.AccountRepo.Received(1).PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(preAuthHash);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_allows_authenticator_second_when_delivered_challenge_window_is_stale()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildSelectedComboSession(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, code: null);
        session.completedMethods = [TwoFactorAuthMethod.SMS_KEY];
        session.currentExpectedMethod = TwoFactorAuthMethod.AUTHENTICATOR_APP;
        session.challengedMethod = TwoFactorAuthMethod.AUTHENTICATOR_APP;
        session.state = TwoFactorSessionState.AwaitingAuthenticatorCode;
        session.challengeExpiration = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromSeconds(1));
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        var verifier = Substitute.For<IAuthenticatorAppLoginVerifier>();
        verifier.VerifyForLoginAsync(session.accountId, "654321", Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatorAppLoginVerificationResult.Success()));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_NEW_LOGIN_PROMOTED")));
        harness.ActiveUserCacheService.SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.RequestServices = new ServiceCollection()
            .AddSingleton(verifier)
            .BuildServiceProvider();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("654321", TwoFactorAuthMethod.AUTHENTICATOR_APP));

        var response = AccountControllerHarness.ExtractData(actionResult, StatusCodes.Status200OK);
        response.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        response.accessToken.ShouldBe(finalToken);
        await verifier.Received(1).VerifyForLoginAsync(session.accountId, "654321", Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await harness.TwoFactorSessionService.Received(1).RevokeSession(preAuthHash);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_accepts_email_first_for_email_and_authenticator_without_promoting()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildSelectedComboSession(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, preAuthHash, session);
        harness.AccountRepo.RecordTwoFactorChallengeIssued(
                session.accountId,
                session.accountSecurityStamp,
                Arg.Is<string>(value => value == preAuthHash),
                TwoFactorAuthMethod.AUTHENTICATOR_APP,
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
                Arg.Any<Instant?>())
            .Returns(call => Task.FromResult<TwoFactorChallengeCommandResult?>(new TwoFactorChallengeCommandResult(
                true,
                "TWO_FACTOR_CHALLENGE_ISSUED",
                0,
                session.challengeResends,
                call.ArgAt<Instant>(7),
                call.ArgAt<Instant>(8))));
        harness.TwoFactorSessionService.SetSession(preAuthHash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        var envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.accessToken.ShouldBeNull();
        envelope.data.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
        envelope.data.currentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        envelope.data.completedTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.EMAIL]);
        envelope.data.remainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().PromoteTwoFactorNewLogin(default, default!, default, default!, default!);
    }

    private static void PrepareValidPendingSession(AccountControllerHarness harness, string preAuthToken, string preAuthHash, TwoFactorSession session)
    {
        harness.TwoFactorSessionService.GetSession(preAuthHash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.JwtUtility.ValidateAccessToken(preAuthToken, session.preAuthRefreshToken, Arg.Any<Instant>(), session.expiration, JsonWebTokenPurpose.PreAuthTwoFactor)
            .Returns(Task.FromResult<(IntraMessage, string?)>((IntraMessage.TOKEN_PASSED_VALIDATION, session.webKey)));
        harness.AccountRepo.IsPendingTwoFactorSessionCurrent(session.accountId, preAuthHash, session.accountSecurityStamp).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.RevokeSession(preAuthHash).Returns(Task.FromResult(true));
    }

    private static TwoFactorSession BuildSelectedComboSession(TwoFactorAuthConfiguration configuration, string? code)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        List<TwoFactorAuthMethod> requiredMethods = configuration switch
        {
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP => [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP => [TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP],
            _ => throw new ArgumentOutOfRangeException(nameof(configuration), configuration, null)
        };
        TwoFactorAuthMethod firstMethod = requiredMethods[0];

        var session = new TwoFactorSession(
            Guid.NewGuid(),
            "web-key",
            Enumerable.Repeat((byte)7, 64).ToArray(),
            requiredMethods,
            ["authenticator-app-user-1"],
            requiredMethods.Contains(TwoFactorAuthMethod.SMS_KEY) ? ["5555550101"] : null,
            requiredMethods.Contains(TwoFactorAuthMethod.SMS_KEY) ? ["1"] : null,
            requiredMethods.Contains(TwoFactorAuthMethod.EMAIL) ? ["reader@example.com"] : null,
            0,
            null,
            1,
            0,
            requiredMethods.Contains(TwoFactorAuthMethod.SMS_KEY) ? (short)1 : (short)0,
            now,
            now.Plus(Duration.FromMinutes(5)),
            FeatureSet.basic,
            null,
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-000000000003"));

        session.selectedConfiguration = configuration;
        session.requiredMethods = requiredMethods;
        session.completedMethods = [];
        session.currentExpectedMethod = firstMethod;
        session.challengedMethod = firstMethod;
        session.state = firstMethod == TwoFactorAuthMethod.SMS_KEY
            ? TwoFactorSessionState.AwaitingSmsCode
            : TwoFactorSessionState.AwaitingEmailCode;
        session.chosenDestination = 0;
        session.challengeExpiration = now.Plus(Duration.FromMinutes(3));
        if (code != null)
        {
            session.challengeCodeHash = TwoFactorChallengeCodeUtility.Hash(code, "test-two-factor-pepper");
            session.intraCodeKey = session.challengeCodeHash;
        }

        return session;
    }


    private static TwoFactorSession BuildChallengedSession(
        TwoFactorAuthMethod method,
        string? code = null,
        string? priorActiveAccessTokenHash = null)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = new TwoFactorSession(
            Guid.NewGuid(),
            "web-key",
            Enumerable.Repeat((byte)7, 64).ToArray(),
            [method],
            method == TwoFactorAuthMethod.AUTHENTICATOR_APP ? ["authenticator-app-user-1"] : null,
            method == TwoFactorAuthMethod.SMS_KEY ? ["5555550101"] : null,
            method == TwoFactorAuthMethod.SMS_KEY ? ["1"] : null,
            method == TwoFactorAuthMethod.EMAIL ? ["reader@example.com"] : null,
            0,
            null,
            method == TwoFactorAuthMethod.AUTHENTICATOR_APP ? (short)1 : (short)0,
            0,
            method == TwoFactorAuthMethod.SMS_KEY ? (short)1 : (short)0,
            now,
            now.Plus(Duration.FromMinutes(5)),
            FeatureSet.basic,
            null,
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-000000000003"),
            priorActiveAccessTokenHash);

        session.selectedConfiguration = method switch
        {
            TwoFactorAuthMethod.EMAIL => TwoFactorAuthConfiguration.EMAIL,
            TwoFactorAuthMethod.SMS_KEY => TwoFactorAuthConfiguration.SMS,
            TwoFactorAuthMethod.AUTHENTICATOR_APP => TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
            _ => null
        };
        session.requiredMethods = [method];
        session.completedMethods = [];
        session.currentExpectedMethod = method;
        session.state = method switch
        {
            TwoFactorAuthMethod.EMAIL => TwoFactorSessionState.AwaitingEmailCode,
            TwoFactorAuthMethod.SMS_KEY => TwoFactorSessionState.AwaitingSmsCode,
            TwoFactorAuthMethod.AUTHENTICATOR_APP => TwoFactorSessionState.AwaitingAuthenticatorCode,
            _ => TwoFactorSessionState.SelectionRequired
        };
        session.challengedMethod = method;
        session.chosenDestination = 0;
        session.challengeExpiration = now.Plus(Duration.FromMinutes(3));

        if (code != null)
        {
            session.challengeCodeHash = TwoFactorChallengeCodeUtility.Hash(code, "test-two-factor-pepper");
            session.intraCodeKey = session.challengeCodeHash;
        }

        return session;
    }
}
