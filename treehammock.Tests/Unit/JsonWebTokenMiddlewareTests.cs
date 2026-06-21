using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class JsonWebTokenMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_without_access_token_calls_next_once_and_leaves_context_unauthenticated()
    {
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBeNull();
        context.Items[AuthContextItems.WebKey].ShouldBeNull();
        context.Items[AuthContextItems.ActiveSession].ShouldBeNull();
        _ = activeUsers.DidNotReceiveWithAnyArgs().GetSession(default!);
        _ = sessionRepo.DidNotReceiveWithAnyArgs().GetSession(default!);
    }

    [Fact]
    public async Task InvokeAsync_with_valid_cached_session_sets_context_items_and_calls_next_once()
    {
        const string accessToken = "cached-access-token";
        const string webKey = "web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldNotBeNull();
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(AccessTokenHashUtility.Hash(accessToken));
        ReferenceEquals(context.Items[AuthContextItems.ActiveSession], session).ShouldBeTrue();
        await activeUsers.Received(1).SetSession(AccessTokenHashUtility.Hash(accessToken), session, Arg.Any<TimeSpan>());
        _ = sessionRepo.DidNotReceiveWithAnyArgs().GetSession(default!);
    }


    [Theory]
    [InlineData(CachedSessionTrustStatus.SessionNotFound)]
    [InlineData(CachedSessionTrustStatus.AccountNotFound)]
    [InlineData(CachedSessionTrustStatus.SecurityStampMismatch)]
    [InlineData(CachedSessionTrustStatus.AccountSecurityStampMismatch)]
    public async Task InvokeAsync_with_stale_cached_session_clears_token_without_authenticating(CachedSessionTrustStatus staleStatus)
    {
        const string accessToken = "stale-cached-access-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var session = ActiveSession(expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(staleStatus, session.accessExpiration, session.sessionExpiration, session.cutOff, Guid.NewGuid(), session.accountSecurityStamp)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp);
        await activeUsers.Received(1).RevokeSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_and_database_cutoff_update_clears_token_without_authenticating()
    {
        const string accessToken = "cutoff-updated-cached-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var session = ActiveSession(
            expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
            cutOff: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(30)));
        Instant databaseCutOff = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, databaseCutOff, session.securityStamp, session.accountSecurityStamp)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp);
        await activeUsers.Received(1).RevokeSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_uses_database_access_expiration_before_jwt_validation()
    {
        const string accessToken = "cached-token-db-shortened-access";
        const string webKey = "db-shortened-access-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = ActiveSession(expiration: now.Plus(Duration.FromMinutes(30)));
        Instant databaseAccessExpiration = now.Plus(Duration.FromMinutes(5));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(
                CachedSessionTrustStatus.Valid,
                databaseAccessExpiration,
                session.sessionExpiration,
                session.cutOff,
                session.securityStamp,
                session.accountSecurityStamp,
                "VALID")));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), databaseAccessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        session.accessExpiration.ShouldBe(databaseAccessExpiration);
        await jwtUtils.Received(1).ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), databaseAccessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>());
        await activeUsers.Received(1).SetSession(
            expectedHash,
            Arg.Is<ActiveSession>(cached => cached.accessExpiration == databaseAccessExpiration),
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_and_database_access_expiration_expired_clears_token_without_authenticating()
    {
        const string accessToken = "cached-token-db-expired-access";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = ActiveSession(expiration: now.Plus(Duration.FromMinutes(30)));
        Instant databaseAccessExpiration = now.Minus(Duration.FromMinutes(1));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(
                CachedSessionTrustStatus.SessionExpired,
                databaseAccessExpiration,
                session.sessionExpiration,
                session.cutOff,
                session.securityStamp,
                session.accountSecurityStamp,
                "SESSION_EXPIRED")));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).RevokeSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cached_session_and_database_session_expiration_expired_clears_token_without_authenticating()
    {
        const string accessToken = "cached-token-db-expired-session";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = ActiveSession(expiration: now.Plus(Duration.FromMinutes(30)));
        Instant databaseSessionExpiration = now.Minus(Duration.FromMinutes(1));
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(
                CachedSessionTrustStatus.SessionExpired,
                session.accessExpiration,
                databaseSessionExpiration,
                session.cutOff,
                session.securityStamp,
                session.accountSecurityStamp,
                "SESSION_EXPIRED")));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).RevokeSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cutoff_expired_cached_session_clears_token_without_authenticating()
    {
        const string accessToken = "cutoff-expired-cached-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var session = ActiveSession(
            expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
            cutOff: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).RevokeSession(expectedHash);
        await sessionRepo.Received(1).ExpireSession(expectedHash, null);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_with_cutoff_expired_database_session_clears_token_without_cache_rehydrate()
    {
        const string accessToken = "cutoff-expired-database-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var storedSession = StoredSession(
            accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
            cutOff: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).GetSession(expectedHash);
        await activeUsers.Received(1).RevokeSession(expectedHash);
        await sessionRepo.Received(1).ExpireSession(expectedHash, null);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_cache_misses_uses_database_session_before_validation()
    {
        const string accessToken = "database-backed-token";
        const string webKey = "db-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        ActiveSession authenticatedSession = context.Items[AuthContextItems.ActiveSession].ShouldBeOfType<ActiveSession>();
        authenticatedSession.accountId.ShouldBe(storedSession.accountId);
        authenticatedSession.accountSecurityStamp.ShouldBe(storedSession.accountSecurityStamp);
        await sessionRepo.Received(1).GetSession(AccessTokenHashUtility.Hash(accessToken));
        await activeUsers.Received(1).SetSession(
            AccessTokenHashUtility.Hash(accessToken),
            Arg.Is<ActiveSession>(session =>
                session.accessExpiration == storedSession.accessExpiration &&
                session.sessionExpiration == storedSession.sessionExpiration),
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task InvokeAsync_when_cache_misses_uses_database_access_expiration_not_hard_session_expiration()
    {
        const string accessToken = "database-backed-split-expiration-token";
        const string webKey = "db-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant accessExpiration = now.Plus(Duration.FromMinutes(5));
        Instant sessionExpiration = now.Plus(Duration.FromDays(7));
        var storedSession = StoredSession(accessExpiration: accessExpiration, sessionExpiration: sessionExpiration);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items["webKey"].ShouldBe(webKey);
        await jwtUtils.Received(1).ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>());
        await activeUsers.Received(1).SetSession(
            AccessTokenHashUtility.Hash(accessToken),
            Arg.Is<ActiveSession>(session =>
                session.accessExpiration == accessExpiration &&
                session.sessionExpiration == sessionExpiration),
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task InvokeAsync_when_database_access_expiration_is_expired_rejects_even_when_hard_session_is_valid()
    {
        const string accessToken = "database-backed-expired-access-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant accessExpiration = now.Minus(Duration.FromMinutes(1));
        Instant sessionExpiration = now.Plus(Duration.FromDays(7));
        var storedSession = StoredSession(accessExpiration: accessExpiration, sessionExpiration: sessionExpiration);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_EXPIRED_VALIDATION, (string?)null)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await jwtUtils.Received(1).ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>());
    }

    [Fact]
    public async Task InvokeAsync_with_refreshable_token_under_refresh_limit_rotates_token_and_sets_response_header()
    {
        const string accessToken = "about-to-expire-token";
        const string refreshedToken = "refreshed-token";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Request.Headers["AccessToken"].ToString().ShouldBe(accessToken);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(refreshedHash);
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        ActiveSession refreshedContextSession = context.Items[AuthContextItems.ActiveSession].ShouldBeOfType<ActiveSession>();
        refreshedContextSession.accountId.ShouldBe(session.accountId);
        refreshedContextSession.refreshes.ShouldBe((short)(session.refreshes + 1));
        refreshedContextSession.accountSecurityStamp.ShouldBe(session.accountSecurityStamp);
        await sessionRepo.Received(1).RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>());
        _ = sessionRepo.DidNotReceive().SetSession(Arg.Any<string>(), Arg.Any<Session>());
        _ = sessionRepo.DidNotReceive().ExpireSession(oldHash, null);
        await activeUsers.Received(1).SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        await activeUsers.Received(1).RevokeSession(oldHash);
    }

    [Fact]
    public async Task InvokeAsync_when_refreshing_token_uses_short_access_expiration_not_session_lifespan()
    {
        const string accessToken = "about-to-expire-token-short-expiration";
        const string refreshedToken = "refreshed-token-short-expiration";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        Instant before = SystemClock.Instance.GetCurrentInstant();
        var session = ActiveSession(
            refreshes: 0,
            expiration: before.Plus(Duration.FromMinutes(5)),
            createdOn: before,
            sessionLifespan: Period.FromDays(7));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        Instant after = SystemClock.Instance.GetCurrentInstant();
        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        await sessionRepo.Received(1).RotateActiveSession(
            session.accountId,
            oldHash,
            refreshedHash,
            Arg.Is<Session>(stored =>
                stored.accessExpiration >= before.Plus(Duration.FromMinutes(settings.RefreshTokenAliveMinutes_Short)) &&
                stored.accessExpiration <= after.Plus(Duration.FromMinutes(settings.RefreshTokenAliveMinutes_Short)) &&
                stored.accessExpiration <= stored.sessionExpiration &&
                stored.sessionExpiration == session.sessionExpiration &&
                stored.sessionLifespan == session.sessionLifespan));
        await activeUsers.Received(1).SetSession(
            refreshedHash,
            Arg.Is<ActiveSession>(refreshed =>
                refreshed.accessExpiration >= before.Plus(Duration.FromMinutes(settings.RefreshTokenAliveMinutes_Short)) &&
                refreshed.accessExpiration <= after.Plus(Duration.FromMinutes(settings.RefreshTokenAliveMinutes_Short)) &&
                refreshed.sessionExpiration == session.sessionExpiration),
            Arg.Is<TimeSpan>(ttl => ttl <= TimeSpan.FromMinutes(settings.RefreshTokenAliveMinutes_Short) && ttl > TimeSpan.Zero));
    }

    [Fact]
    public async Task InvokeAsync_when_refreshing_token_does_not_extend_beyond_hard_session_expiration()
    {
        const string accessToken = "about-to-expire-token-hard-limit";
        const string refreshedToken = "refreshed-token-hard-limit";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant createdOn = now.Minus(Duration.FromDays(7)).Plus(Duration.FromMinutes(10));
        var session = ActiveSession(
            refreshes: 0,
            expiration: now.Plus(Duration.FromMinutes(5)),
            createdOn: createdOn,
            sessionLifespan: Period.FromDays(7));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        await sessionRepo.Received(1).RotateActiveSession(
            session.accountId,
            oldHash,
            refreshedHash,
            Arg.Is<Session>(stored =>
                stored.accessExpiration <= session.sessionExpiration &&
                stored.accessExpiration <= stored.sessionExpiration &&
                stored.sessionExpiration == session.sessionExpiration &&
                stored.sessionLifespan == session.sessionLifespan));
        await activeUsers.Received(1).SetSession(
            refreshedHash,
            Arg.Is<ActiveSession>(refreshed => refreshed.accessExpiration == session.sessionExpiration),
            Arg.Is<TimeSpan>(ttl => ttl <= TimeSpan.FromMinutes(10) && ttl > TimeSpan.Zero));
    }

    [Fact]
    public async Task InvokeAsync_when_refreshing_token_with_cutoff_after_short_period_still_uses_short_access_expiration()
    {
        const string accessToken = "about-to-expire-token-cutoff-after-short";
        const string refreshedToken = "refreshed-token-cutoff-after-short";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant cutOff = now.Plus(Duration.FromMinutes(20));
        var session = ActiveSession(
            refreshes: 0,
            expiration: now.Plus(Duration.FromMinutes(5)),
            cutOff: cutOff,
            createdOn: now,
            sessionLifespan: Period.FromDays(7));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });
        Instant before = SystemClock.Instance.GetCurrentInstant();

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        Instant after = SystemClock.Instance.GetCurrentInstant();
        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        await sessionRepo.Received(1).RotateActiveSession(
            session.accountId,
            oldHash,
            refreshedHash,
            Arg.Is<Session>(stored =>
                stored.accessExpiration <= session.sessionExpiration &&
                stored.accessExpiration <= stored.sessionExpiration &&
                stored.sessionExpiration == session.sessionExpiration &&
                stored.sessionLifespan == session.sessionLifespan));
        await activeUsers.Received(1).SetSession(
            refreshedHash,
            Arg.Is<ActiveSession>(refreshed =>
                refreshed.accessExpiration >= before.Plus(Duration.FromMinutes(settings.RefreshTokenAliveMinutes_Short)) &&
                refreshed.accessExpiration <= after.Plus(Duration.FromMinutes(settings.RefreshTokenAliveMinutes_Short)) &&
                refreshed.accessExpiration < cutOff &&
                refreshed.EffectiveSessionExpiration == cutOff),
            Arg.Is<TimeSpan>(ttl => ttl <= TimeSpan.FromMinutes(settings.RefreshTokenAliveMinutes_Short) && ttl > TimeSpan.Zero));
    }

    [Fact]
    public async Task InvokeAsync_when_refreshing_token_does_not_extend_beyond_account_cutoff()
    {
        const string accessToken = "about-to-expire-token-cutoff-limit";
        const string refreshedToken = "refreshed-token-cutoff-limit";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant cutOff = now.Plus(Duration.FromMinutes(8));
        var session = ActiveSession(
            refreshes: 0,
            expiration: now.Plus(Duration.FromMinutes(5)),
            cutOff: cutOff,
            createdOn: now,
            sessionLifespan: Period.FromDays(7));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        await sessionRepo.Received(1).RotateActiveSession(
            session.accountId,
            oldHash,
            refreshedHash,
            Arg.Is<Session>(stored =>
                stored.accessExpiration <= session.sessionExpiration &&
                stored.accessExpiration <= stored.sessionExpiration &&
                stored.sessionExpiration == session.sessionExpiration &&
                stored.sessionLifespan == session.sessionLifespan));
        await activeUsers.Received(1).SetSession(
            refreshedHash,
            Arg.Is<ActiveSession>(refreshed => refreshed.accessExpiration == cutOff && refreshed.EffectiveSessionExpiration == cutOff),
            Arg.Is<TimeSpan>(ttl => ttl <= TimeSpan.FromMinutes(8) && ttl > TimeSpan.Zero));
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_is_missing_calls_next_without_validation()
    {
        const string accessToken = "missing-database-session-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(null));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await sessionRepo.Received(1).GetSession(AccessTokenHashUtility.Hash(accessToken));
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_refresh_rotation_fails_does_not_revoke_old_session()
    {
        const string accessToken = "about-to-expire-token-with-failed-rotation";
        const string refreshedToken = "failed-refresh-token";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Failed)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(string.Empty);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        _ = activeUsers.DidNotReceiveWithAnyArgs().RevokeSession(default!);
        _ = sessionRepo.DidNotReceiveWithAnyArgs().ExpireSession(default!, default);
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }


    [Fact]
    public async Task InvokeAsync_when_refresh_rotation_reports_old_session_mismatch_revokes_stale_old_cache()
    {
        const string accessToken = "about-to-expire-token-after-logout";
        const string refreshedToken = "refreshed-token-after-logout";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(oldHash).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.OldSessionMismatch)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(string.Empty);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        await sessionRepo.Received(1).RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>());
        await activeUsers.Received(1).RevokeSession(oldHash);
        _ = activeUsers.DidNotReceive().SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        _ = sessionRepo.DidNotReceive().ExpireSession(refreshedHash, null);
    }

    [Fact]
    public async Task InvokeAsync_when_refresh_rotation_throws_fails_without_cache_or_database_cleanup()
    {
        const string accessToken = "about-to-expire-token-rotation-throws";
        const string refreshedToken = "refreshed-token-rotation-throws";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(_ => Task.FromException<SessionRotationResult?>(new InvalidOperationException("rotation failed")));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(string.Empty);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        _ = activeUsers.DidNotReceiveWithAnyArgs().RevokeSession(default!);
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
        _ = sessionRepo.DidNotReceiveWithAnyArgs().ExpireSession(default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_old_cache_revoke_returns_false_still_returns_refreshed_token()
    {
        const string accessToken = "about-to-expire-token-old-cache-revoke-fails";
        const string refreshedToken = "refreshed-token-old-cache-revoke-fails";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        activeUsers.RevokeSession(oldHash).Returns(Task.FromResult(false));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(string.Empty);
        await sessionRepo.Received(1).RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>());
        await activeUsers.Received(1).SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        await activeUsers.Received(1).RevokeSession(oldHash);
        _ = sessionRepo.DidNotReceive().ExpireSession(refreshedHash, null);
    }

    [Fact]
    public async Task InvokeAsync_when_old_cache_revoke_throws_still_returns_refreshed_token()
    {
        const string accessToken = "about-to-expire-token-old-cache-revoke-throws";
        const string refreshedToken = "refreshed-token-old-cache-revoke-throws";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(true));
        activeUsers.RevokeSession(oldHash).Returns(_ => Task.FromException<bool>(new InvalidOperationException("old cache revoke failed")));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(string.Empty);
        await activeUsers.Received(1).SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        _ = activeUsers.Received(1).RevokeSession(oldHash);
        _ = sessionRepo.DidNotReceive().ExpireSession(refreshedHash, null);
    }

    [Fact]
    public async Task InvokeAsync_when_refreshed_cache_write_returns_false_still_returns_refreshed_token_without_db_rollback()
    {
        const string accessToken = "about-to-expire-token-cache-write-false";
        const string refreshedToken = "refreshed-token-cache-write-false";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        activeUsers.SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(false));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(string.Empty);
        await activeUsers.Received(1).RevokeSession(oldHash);
        await activeUsers.Received(1).SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        _ = activeUsers.DidNotReceive().RevokeSession(refreshedHash);
        _ = sessionRepo.DidNotReceive().ExpireSession(refreshedHash, null);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(refreshedHash);
    }

    [Fact]
    public async Task InvokeAsync_when_refreshed_cache_write_throws_still_returns_refreshed_token_without_db_rollback()
    {
        const string accessToken = "about-to-expire-token-cache-write-throws";
        const string refreshedToken = "refreshed-token-cache-write-throws";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        string oldHash = AccessTokenHashUtility.Hash(accessToken);
        string refreshedHash = AccessTokenHashUtility.Hash(refreshedToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        activeUsers.SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>())
            .Returns(_ => Task.FromException<bool>(new InvalidOperationException("refreshed cache write failed")));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        jwtUtils.GenerateAccessToken(Arg.Any<byte[]>(), webKey, JsonWebTokenPurpose.Active).Returns(refreshedToken);
        sessionRepo.RotateActiveSession(session.accountId, oldHash, refreshedHash, Arg.Any<Session>())
            .Returns(Task.FromResult<SessionRotationResult?>(new SessionRotationResult(SessionRotationStatus.Succeeded)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AccessToken"].ToString().ShouldBe(refreshedToken);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(string.Empty);
        await activeUsers.Received(1).RevokeSession(oldHash);
        _ = activeUsers.Received(1).SetSession(refreshedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
        _ = activeUsers.DidNotReceive().RevokeSession(refreshedHash);
        _ = sessionRepo.DidNotReceive().ExpireSession(refreshedHash, null);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(refreshedHash);
    }

    [Fact]
    public async Task InvokeAsync_with_expired_token_over_refresh_limit_tells_client_to_clear_token()
    {
        const string accessToken = "fully-expired-token";
        const string webKey = "refresh-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: (short)settings.RefreshTokenGenRetries, expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_AT_EXPIRATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        _ = sessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!);
    }


    [Fact]
    public async Task InvokeAsync_with_fully_expired_token_does_not_refresh_and_tells_client_to_clear_token()
    {
        const string accessToken = "already-expired-token";
        const string webKey = "expired-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var session = ActiveSession(refreshes: 0, expiration: SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(session));
        sessionRepo.ValidateCachedSessionTrust(Arg.Any<string>(), session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(CachedSessionTrustStatus.Valid, session.accessExpiration, session.sessionExpiration, session.cutOff, session.securityStamp, session.accountSecurityStamp)));
        jwtUtils.ValidateAccessToken(accessToken, session.refreshToken, Arg.Any<Instant>(), session.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_EXPIRED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        _ = sessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!);
        _ = activeUsers.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_is_used_rehydrates_cache_with_features_and_cutoff()
    {
        const string accessToken = "database-backed-token-with-metadata";
        const string webKey = "db-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        Instant cutOff = createdOn.Plus(Duration.FromMinutes(20));
        var storedSession = new Session(
            Guid.NewGuid(),
            Enumerable.Repeat((byte)7, 64).ToArray(),
            0,
            3,
            createdOn,
            Period.FromMinutes(30),
            createdOn.Plus(Duration.FromMinutes(10)),
            createdOn.Plus(Duration.FromMinutes(25)),
            cutOff,
            FeatureSet.premium,
            accountSecurityStamp: Guid.Parse("77777777-8888-9999-aaaa-bbbbbbbbbbbb"));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        nextCalls.ShouldBe(1);
        await activeUsers.Received(1).SetSession(
            AccessTokenHashUtility.Hash(accessToken),
            Arg.Is<ActiveSession>(session =>
                session.cutOff == cutOff &&
                session.features == FeatureSet.premium &&
                session.features == FeatureSet.premium),
            Arg.Any<TimeSpan>());
    }


    [Fact]
    public async Task InvokeAsync_when_active_cache_payload_is_stale_revokes_cache_and_uses_database_session()
    {
        const string accessToken = "stale-active-cache-db-backed-token";
        const string webKey = "db-fallback-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>())
            .Returns(_ => Task.FromException<ActiveSession?>(new StaleActiveSessionCachePayloadException("legacy active payload")));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).GetSession(expectedHash);
        await activeUsers.Received(1).RevokeSession(expectedHash);
        await sessionRepo.Received(1).GetSession(expectedHash);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task InvokeAsync_when_active_cache_payload_is_stale_and_database_misses_revokes_cache_and_leaves_request_unauthenticated()
    {
        const string accessToken = "stale-active-cache-db-misses-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>())
            .Returns(_ => Task.FromException<ActiveSession?>(new StaleActiveSessionCachePayloadException("legacy active payload")));
        activeUsers.RevokeSession(Arg.Any<string>()).Returns(Task.FromResult(true));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(null));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).GetSession(expectedHash);
        await activeUsers.Received(1).RevokeSession(expectedHash);
        await sessionRepo.Received(1).GetSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_cache_read_throws_uses_database_session_before_validation()
    {
        const string accessToken = "cache-read-fails-db-backed-token";
        const string webKey = "db-fallback-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>())
            .Returns(_ => Task.FromException<ActiveSession?>(new InvalidOperationException("redis read failed")));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).GetSession(expectedHash);
        await sessionRepo.Received(1).GetSession(expectedHash);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task InvokeAsync_when_cache_read_throws_and_database_misses_leaves_request_unauthenticated()
    {
        const string accessToken = "cache-read-fails-db-misses-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>())
            .Returns(_ => Task.FromException<ActiveSession?>(new InvalidOperationException("redis read failed")));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(null));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBeNull();
        context.Items["webKey"].ShouldBeNull();
        await activeUsers.Received(1).GetSession(expectedHash);
        await sessionRepo.Received(1).GetSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_cache_rehydrate_throws_still_authenticates_request()
    {
        const string accessToken = "cache-rehydrate-throws-db-backed-token";
        const string webKey = "db-backed-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>())
            .Returns(_ => Task.FromException<bool>(new InvalidOperationException("redis write failed")));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_cache_rehydrate_returns_false_still_authenticates_request()
    {
        const string accessToken = "cache-rehydrate-false-db-backed-token";
        const string webKey = "db-backed-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(Task.FromResult(false));
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items["hashedAccessToken"].ShouldBe(expectedHash);
        context.Items["webKey"].ShouldBe(webKey);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
    }


    [Fact]
    public async Task InvokeAsync_when_cache_read_times_out_uses_database_session_before_validation()
    {
        const string accessToken = "cache-read-timeout-db-backed-token";
        const string webKey = "timeout-db-fallback-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var fallbackSettings = TestFallbackSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var cacheRead = new TaskCompletionSource<ActiveSession?>();
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(cacheRead.Task);
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings), Options.Create(fallbackSettings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(expectedHash);
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        await sessionRepo.Received(1).GetSession(expectedHash);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task InvokeAsync_when_cache_read_times_out_and_database_times_out_denies_without_jwt_validation()
    {
        const string accessToken = "cache-read-timeout-db-timeout-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var fallbackSettings = TestFallbackSettings();
        var cacheRead = new TaskCompletionSource<ActiveSession?>();
        var dbRead = new TaskCompletionSource<Session?>();
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(cacheRead.Task);
        sessionRepo.GetSession(Arg.Any<string>()).Returns(dbRead.Task);
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()), Options.Create(fallbackSettings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items[AuthContextItems.HashedAccessToken].ShouldBeNull();
        context.Items[AuthContextItems.WebKey].ShouldBeNull();
        await sessionRepo.Received(1).GetSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_cached_session_trust_validation_times_out_denies_without_jwt_validation()
    {
        const string accessToken = "cached-session-trust-timeout-token";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var fallbackSettings = TestFallbackSettings();
        var session = ActiveSession(expiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var trustCheck = new TaskCompletionSource<CachedSessionTrustResult?>();
        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(expectedHash).Returns(Task.FromResult<ActiveSession?>(session));
        activeUsers.RevokeSession(expectedHash).Returns(Task.FromResult(true));
        sessionRepo.ValidateCachedSessionTrust(expectedHash, session.accountId, session.securityStamp, session.accountSecurityStamp)
            .Returns(trustCheck.Task);
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(TestJwtSettings()), Options.Create(fallbackSettings));

        nextCalls.ShouldBe(1);
        context.Response.Headers["AppStatus"].ToString().ShouldBe(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        context.Items[AuthContextItems.ActiveSession].ShouldBeNull();
        await activeUsers.Received(1).RevokeSession(expectedHash);
        _ = jwtUtils.DidNotReceiveWithAnyArgs().ValidateAccessToken(default!, default!, default, default, default!, default);
    }

    [Fact]
    public async Task InvokeAsync_when_database_session_cache_rehydrate_times_out_still_authenticates_request()
    {
        const string accessToken = "cache-rehydrate-timeout-db-backed-token";
        const string webKey = "db-backed-timeout-web-key";
        int nextCalls = 0;
        var context = new DefaultHttpContext();
        context.Request.Headers["AccessToken"] = accessToken;
        var settings = TestJwtSettings();
        var fallbackSettings = TestFallbackSettings();
        var storedSession = StoredSession(accessExpiration: SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)));
        var cacheWrite = new TaskCompletionSource<bool>();
        var activeUsers = Substitute.For<IActiveUserCacheService>();
        var jwtUtils = Substitute.For<IJsonWebTokenUtility>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        activeUsers.GetSession(Arg.Any<string>()).Returns(Task.FromResult<ActiveSession?>(null));
        activeUsers.SetSession(Arg.Any<string>(), Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>()).Returns(cacheWrite.Task);
        sessionRepo.GetSession(Arg.Any<string>()).Returns(Task.FromResult<Session?>(storedSession));
        jwtUtils.ValidateAccessToken(accessToken, storedSession.refreshToken, Arg.Any<Instant>(), storedSession.accessExpiration, JsonWebTokenPurpose.Active, Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)webKey)));
        var middleware = new JsonWebTokenMiddleware(_ =>
        {
            nextCalls++;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, activeUsers, jwtUtils, sessionRepo, Options.Create(settings), Options.Create(fallbackSettings));

        string expectedHash = AccessTokenHashUtility.Hash(accessToken);
        nextCalls.ShouldBe(1);
        context.Items[AuthContextItems.HashedAccessToken].ShouldBe(expectedHash);
        context.Items[AuthContextItems.WebKey].ShouldBe(webKey);
        await activeUsers.Received(1).SetSession(expectedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>());
    }

    private static JWTSettings TestJwtSettings()
    {
        return new JWTSettings
        {
            JsonWebTokenIssuer = "treehammock-tests",
            RefreshTokenGenRetries = 2,
            RefreshTokenAliveDays = 0,
            RefreshTokenAliveHours = 0,
            RefreshTokenAliveMinutes = 30,
            RefreshTokenAliveDays_2FA = 0,
            RefreshTokenAliveHours_2FA = 0,
            RefreshTokenAliveMinutes_2FA = 2,
            RefreshTokenAliveDays_DB = 7,
            RefreshTokenAliveHours_DB = 0,
            RefreshTokenAliveMinutes_DB = 0,
            RefreshTokenAliveDays_Short = 0,
            RefreshTokenAliveHours_Short = 0,
            RefreshTokenAliveMinutes_Short = 15,
            RefreshTokenBytes = 64,
            RefreshWindowMinutes = 10
        };
    }


    private static SessionCacheFallbackSettings TestFallbackSettings()
    {
        return new SessionCacheFallbackSettings
        {
            CacheReadTimeoutMilliseconds = 10,
            CacheWriteTimeoutMilliseconds = 10,
            CacheRevokeTimeoutMilliseconds = 10,
            DatabaseFallbackTimeoutMilliseconds = 10
        };
    }

    private static ActiveSession ActiveSession(
        short refreshes = 0,
        Instant? expiration = null,
        Instant? cutOff = null,
        Instant? createdOn = null,
        Period? sessionLifespan = null)
    {
        Instant sessionCreatedOn = createdOn ?? SystemClock.Instance.GetCurrentInstant();
        Period hardSessionLifespan = sessionLifespan ?? Period.FromMinutes(30);
        Instant hardSessionExpiration = sessionCreatedOn.Plus(hardSessionLifespan.ToDuration());
        return new ActiveSession(
            Guid.NewGuid(),
            Enumerable.Repeat((byte)9, 64).ToArray(),
            refreshes,
            sessionCreatedOn,
            hardSessionLifespan,
            expiration ?? sessionCreatedOn.Plus(Duration.FromMinutes(30)),
            hardSessionExpiration,
            cutOff,
            FeatureSet.basic,
            accountSecurityStamp: Guid.Parse("88888888-9999-aaaa-bbbb-cccccccccccc"));
    }

    private static Session StoredSession(Instant? accessExpiration = null, Instant? sessionExpiration = null, Instant? cutOff = null)
    {
        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        return new Session(
            Guid.NewGuid(),
            Enumerable.Repeat((byte)8, 64).ToArray(),
            0,
            3,
            createdOn,
            Period.FromMinutes(30),
            accessExpiration ?? createdOn.Plus(Duration.FromMinutes(10)),
            sessionExpiration ?? createdOn.Plus(Duration.FromMinutes(30)),
            cutOff,
            accountSecurityStamp: Guid.Parse("99999999-aaaa-bbbb-cccc-dddddddddddd"));
    }
}
