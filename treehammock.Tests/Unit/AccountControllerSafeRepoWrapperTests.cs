using Microsoft.AspNetCore.Http;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class AccountControllerSafeRepoWrapperTests
{
    [Fact]
    public async Task Authenticate_returns_persistence_failure_when_credential_lookup_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL)
            .Returns(_ => Task.FromException<CredentialLookupResult>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("LOGIN_ATTEMPT_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!);
    }

    [Fact]
    public async Task Authenticate_returns_db_persistence_failure_when_session_insert_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL)
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>())
            .Returns(_ => Task.FromException<IntraMessage?>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACTIVE_SESSION_DB_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp);
    }

    [Fact]
    public async Task Authenticate_rolls_back_when_successful_login_finalization_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        const string token = "active-access-token";
        string hash = AccessTokenHashUtility.Hash(token);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL)
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(token);
        harness.SessionRepo.SetSession(hash, Arg.Any<Session>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        harness.ActiveUserCacheService.SetSession(hash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        harness.AccountRepo.SuccessfulLogin(account.accountId, account.accountSecurityStamp)
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("repo boom")));
        harness.ActiveUserCacheService.RevokeSession(hash).Returns(Task.FromResult(true));
        harness.SessionRepo.ExpireSession(hash, null).Returns(Task.FromResult<bool?>(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.ActiveUserCacheService.Received(1).RevokeSession(hash);
        await harness.SessionRepo.Received(1).ExpireSession(hash, null);
    }

    [Fact]
    public async Task Authenticate_already_logged_in_returns_500_when_db_rotation_throws_without_touching_cache()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(
            refreshToken: Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray(),
            hasTwoFactorAuth: false,
            activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL)
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>())
            .Returns(_ => Task.FromException<SessionRotationResult?>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(oldHash);
        await harness.ActiveUserCacheService.DidNotReceive().SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task Authenticate_returns_two_factor_lookup_failure_when_details_lookup_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(hasTwoFactorAuth: true, twoFactorAuthMethod: TwoFactorAuthMethod.EMAIL);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL)
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId)
            .Returns(_ => Task.FromException<TwoFactorDetailsLookupResult>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_DETAILS_LOOKUP_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task Authenticate_revokes_pending_cache_when_pending_db_write_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(hasTwoFactorAuth: true, twoFactorAuthMethod: TwoFactorAuthMethod.EMAIL);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL)
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId)
            .Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(new TwoFactorDetails([TwoFactorAuthMethod.EMAIL], null, null, null, ["reader@example.com"]))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey, JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pre-auth-token");
        string preAuthHash = AccessTokenHashUtility.Hash("pre-auth-token");
        harness.TwoFactorSessionService.SetSession(preAuthHash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        harness.AccountRepo.BeginTwoFactorSession(account.accountId, account.accountSecurityStamp, Arg.Any<short?>(), preAuthHash, Arg.Any<Instant>(), Arg.Any<Instant>())
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("repo boom")));
        harness.TwoFactorSessionService.RevokeSession(preAuthHash).Returns(Task.FromResult(true));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PREAUTH_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.TwoFactorSessionService.Received(1).RevokeSession(preAuthHash);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_returns_validation_failure_when_pending_db_validation_throws()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        harness.TwoFactorSessionService.GetSession(preAuthHash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.JwtUtility.ValidateAccessToken(preAuthToken, session.preAuthRefreshToken, Arg.Any<Instant>(), session.expiration, JsonWebTokenPurpose.PreAuthTwoFactor)
            .Returns(Task.FromResult<(IntraMessage, string?)>((IntraMessage.TOKEN_PASSED_VALIDATION, session.webKey)));
        harness.AccountRepo.IsPendingTwoFactorSessionCurrent(session.accountId, preAuthHash, session.accountSecurityStamp)
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_PENDING_SESSION_VALIDATION_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_returns_controlled_failure_when_new_login_promotion_throws()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-active-token";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456");
        PrepareValidPendingSession(harness, preAuthToken, session);
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorNewLogin(session.accountId, preAuthHash, session.accountSecurityStamp, finalHash, Arg.Any<Session>())
            .Returns(_ => Task.FromException<DbCommandResult?>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACTIVE_SESSION_DB_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        _ = harness.ActiveUserCacheService.DidNotReceive().SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        _ = harness.SessionRepo.DidNotReceive().ExpireSession(finalHash, null);
        _ = harness.TwoFactorSessionService.DidNotReceive().RevokeSession(preAuthHash);
    }

    [Fact]
    public async Task TwoFactorAuthenticate_rotation_promotion_throw_returns_controlled_500()
    {
        var harness = new AccountControllerHarness();
        const string preAuthToken = "pending-token";
        const string finalToken = "final-active-token";
        const string priorActiveHash = "prior-active-hash";
        string preAuthHash = AccessTokenHashUtility.Hash(preAuthToken);
        string finalHash = AccessTokenHashUtility.Hash(finalToken);
        var session = BuildChallengedSession(TwoFactorAuthMethod.EMAIL, code: "123456", priorActiveAccessTokenHash: priorActiveHash);
        PrepareValidPendingSession(harness, preAuthToken, session);
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), session.webKey).Returns(finalToken);
        harness.AccountRepo.PromoteTwoFactorRotationLogin(session.accountId, preAuthHash, session.accountSecurityStamp, priorActiveHash, finalHash, Arg.Any<Session>())
            .Returns(_ => Task.FromException<DbCommandResult?>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateTwoFactorController();
        harness.HttpContext.Request.Headers["AccessToken"] = preAuthToken;

        var actionResult = await controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456", TwoFactorAuthMethod.EMAIL));

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_ROTATION_AFTER_FINALIZATION_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(priorActiveHash);
        await harness.ActiveUserCacheService.DidNotReceive().SetSession(finalHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().RotateActiveSession(default, default!, default!, default!);
    }

    private static string PrepareValidPendingSession(AccountControllerHarness harness, string preAuthToken, TwoFactorSession session)
    {
        string hash = AccessTokenHashUtility.Hash(preAuthToken);
        harness.TwoFactorSessionService.GetSession(hash).Returns(Task.FromResult<TwoFactorSession?>(session));
        harness.JwtUtility.ValidateAccessToken(preAuthToken, session.preAuthRefreshToken, Arg.Any<Instant>(), session.expiration, JsonWebTokenPurpose.PreAuthTwoFactor)
            .Returns(Task.FromResult<(IntraMessage, string?)>((IntraMessage.TOKEN_PASSED_VALIDATION, session.webKey)));
        harness.AccountRepo.IsPendingTwoFactorSessionCurrent(session.accountId, hash, session.accountSecurityStamp).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.SetSession(hash, Arg.Any<TwoFactorSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult<bool?>(true));
        harness.TwoFactorSessionService.RevokeSession(hash).Returns(Task.FromResult(true));
        return hash;
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
            null,
            null,
            null,
            method == TwoFactorAuthMethod.EMAIL ? ["reader@example.com"] : null,
            0,
            null,
            0,
            0,
            0,
            now,
            now.Plus(Duration.FromMinutes(5)),
            FeatureSet.basic,
            null,
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-000000000004"),
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
        session.challengeExpiration = now.Plus(Duration.FromMinutes(3));

        if (code != null)
        {
            session.challengeCodeHash = TwoFactorChallengeCodeUtility.Hash(code, "test-two-factor-pepper");
            session.intraCodeKey = session.challengeCodeHash;
        }

        return session;
    }
}
