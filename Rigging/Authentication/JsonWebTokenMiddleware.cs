using System.Security.Cryptography;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using NodaTime;

using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Rigging.Authorization;

// 1.0.0 stores authoritative session state in PostgreSQL and hydrates trusted cache entries from that source.
// Cross-shard Dragonfly replication and a dedicated cache-database topology are future cache/storage design work
// tracked in docs/release/RELEASE_FEATURE_MATRIX_1_0_0.md, not active runtime behavior.

public class JsonWebTokenMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<JsonWebTokenMiddleware> _logger;

    public JsonWebTokenMiddleware(RequestDelegate next, ILogger<JsonWebTokenMiddleware>? logger = null)
    {
        _next = next;
        _logger = logger ?? NullLogger<JsonWebTokenMiddleware>.Instance;
    }

    public async Task InvokeAsync(
        HttpContext context,
        IActiveUserCacheService activeUsers,
        IJsonWebTokenUtility jwtUtils,
        ISessionRepo sessionRepo,
        IOptions<JWTSettings> jwtSettings,
        IOptions<SessionCacheFallbackSettings>? sessionCacheFallbackSettings = null)
    {
        SessionCacheFallbackSettings fallbackSettings = sessionCacheFallbackSettings?.Value ?? new SessionCacheFallbackSettings();

        context.Items[AuthContextItems.HashedAccessToken] = null;
        context.Items[AuthContextItems.WebKey] = null;
        context.Items[AuthContextItems.ActiveSession] = null;

        string? accessToken = AccessTokenTransport.ReadRequestToken(context.Request.Headers);
        if (string.IsNullOrWhiteSpace(accessToken))
        {
            await _next(context);
            return;
        }

        string accessTokenHash;
        try
        {
            accessTokenHash = AccessTokenHashUtility.Hash(accessToken);
        }
        catch
        {
            await _next(context);
            return;
        }

        if (string.IsNullOrWhiteSpace(accessTokenHash))
        {
            await _next(context);
            return;
        }

        Instant currentMoment = SystemClock.Instance.GetCurrentInstant();
        ActiveSession? session = await SafeGetActiveSession(activeUsers, accessTokenHash, fallbackSettings);
        if (session == null)
        {
            session = await TryLoadAuthoritativeSessionFromDatabase(sessionRepo, accessTokenHash, fallbackSettings.DatabaseFallbackTimeout);
            if (session == null)
            {
                context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
                await _next(context);
                return;
            }
        }
        else if (!await ValidateCachedSessionTrust(activeUsers, sessionRepo, accessTokenHash, session, fallbackSettings))
        {
            context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            await _next(context);
            return;
        }

        if (IsSessionHardExpired(session, currentMoment))
        {
            await TryRevokeExpiredSession(activeUsers, sessionRepo, accessTokenHash, fallbackSettings);
            context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            await _next(context);
            return;
        }

        (IntraMessage status, string? webKey) = await jwtUtils.ValidateAccessToken(
            accessToken,
            session.refreshToken,
            currentMoment,
            session.accessExpiration,
            JsonWebTokenPurpose.Active,
            Duration.FromMinutes(jwtSettings.Value.RefreshWindowMinutes));

        if (!string.IsNullOrWhiteSpace(webKey))
        {
            if (status == IntraMessage.TOKEN_PASSED_VALIDATION)
            {
                TimeSpan cacheTtl = CalculateCacheTtl(session, jwtSettings.Value, currentMoment);

                await SafeSetActiveSession(activeUsers, accessTokenHash, session, cacheTtl, "active session cache hydration", fallbackSettings.CacheWriteTimeout);
                context.Items[AuthContextItems.HashedAccessToken] = accessTokenHash;
                context.Items[AuthContextItems.WebKey] = webKey;
                context.Items[AuthContextItems.ActiveSession] = session;
            }
            else if (status == IntraMessage.TOKEN_AT_EXPIRATION && (uint)(session.refreshes + 1) <= jwtSettings.Value.RefreshTokenGenRetries)
            {
                RefreshSessionResult refreshResult = await TryRefreshSession(
                    accessTokenHash,
                    session,
                    webKey,
                    activeUsers,
                    jwtUtils,
                    sessionRepo,
                    jwtSettings.Value,
                    fallbackSettings);

                if (refreshResult.Succeeded)
                {
                    context.Response.Headers["AccessToken"] = refreshResult.AccessToken!;
                    context.Items[AuthContextItems.HashedAccessToken] = refreshResult.AccessTokenHash!;
                    context.Items[AuthContextItems.WebKey] = webKey;
                    context.Items[AuthContextItems.ActiveSession] = refreshResult.Session!;
                }
                else
                {
                    context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
                }
            }
            else if (status == IntraMessage.TOKEN_AT_EXPIRATION && (uint)(session.refreshes + 1) > jwtSettings.Value.RefreshTokenGenRetries)
            {
                context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            }
            else if (status == IntraMessage.TOKEN_EXPIRED_VALIDATION)
            {
                context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
            }
        }
        else
        {
            context.Response.Headers["AppStatus"] = AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString();
        }

        await _next(context);
        return;
    }


    private async Task<bool> ValidateCachedSessionTrust(
        IActiveUserCacheService activeUsers,
        ISessionRepo sessionRepo,
        string accessTokenHash,
        ActiveSession session,
        SessionCacheFallbackSettings fallbackSettings)
    {
        CachedSessionTrustResult? validation = await SafeValidateCachedSessionTrust(sessionRepo, accessTokenHash, session, fallbackSettings.DatabaseFallbackTimeout);
        if (validation?.Succeeded != true)
        {
            await SafeRevokeActiveSession(activeUsers, accessTokenHash, "stale active session cache revoke", fallbackSettings.CacheRevokeTimeout);
            return false;
        }

        if (validation.AccessExpiration is not null)
        {
            session.accessExpiration = validation.AccessExpiration.Value;
        }

        if (validation.SessionExpiration is not null)
        {
            session.sessionExpiration = validation.SessionExpiration.Value;
        }

        session.cutOff = validation.CutOff;

        if (validation.SecurityStamp is not null)
        {
            session.securityStamp = validation.SecurityStamp.Value;
        }

        if (validation.AccountSecurityStamp is not null)
        {
            session.accountSecurityStamp = validation.AccountSecurityStamp.Value;
        }

        return true;
    }

    private async Task<CachedSessionTrustResult?> SafeValidateCachedSessionTrust(
        ISessionRepo sessionRepo,
        string accessTokenHash,
        ActiveSession session,
        TimeSpan timeout)
    {
        try
        {
            CachedSessionTrustResult? result = await WithTimeout(
                sessionRepo.ValidateCachedSessionTrust(accessTokenHash, session.accountId, session.securityStamp, session.accountSecurityStamp),
                timeout,
                timeoutValue: null,
                "active session cache trust validation",
                HashFingerprint(accessTokenHash));
            if (result?.Succeeded != true)
            {
                _logger.LogWarning(
                    "Active session cache trust validation failed with status {Status} and code {Code} for token hash {AccessTokenHashFingerprint} and account {AccountId}.",
                    result?.Status.ToString() ?? "NullResult",
                    result?.Code ?? "NullCode",
                    HashFingerprint(accessTokenHash),
                    session.accountId);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Active session cache trust validation threw for token hash {AccessTokenHashFingerprint} and account {AccountId}.",
                HashFingerprint(accessTokenHash),
                session.accountId);
            return new CachedSessionTrustResult(CachedSessionTrustStatus.Failed, Code: "CACHE_TRUST_VALIDATION_EXCEPTION");
        }
    }

    private async Task<ActiveSession?> SafeGetActiveSession(IActiveUserCacheService activeUsers, string accessTokenHash, SessionCacheFallbackSettings fallbackSettings)
    {
        try
        {
            return await WithTimeout(
                activeUsers.GetSession(accessTokenHash),
                fallbackSettings.CacheReadTimeout,
                timeoutValue: null,
                "active session cache read",
                HashFingerprint(accessTokenHash));
        }
        catch (StaleActiveSessionCachePayloadException ex)
        {
            _logger.LogWarning(
                ex,
                "Active session cache payload was stale or malformed for token hash {AccessTokenHashFingerprint}; revoking cache entry and falling back to database session lookup.",
                HashFingerprint(accessTokenHash));

            await SafeRevokeActiveSession(activeUsers, accessTokenHash, "stale active session cache payload revoke", fallbackSettings.CacheRevokeTimeout);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Active session cache read failed for token hash {AccessTokenHashFingerprint}; falling back to database session lookup.",
                HashFingerprint(accessTokenHash));
            return null;
        }
    }

    private async Task<bool> SafeSetActiveSession(
        IActiveUserCacheService activeUsers,
        string accessTokenHash,
        ActiveSession session,
        TimeSpan cacheTtl,
        string operationName,
        TimeSpan timeout)
    {
        try
        {
            bool result = await WithTimeout(
                activeUsers.SetSession(accessTokenHash, session, cacheTtl),
                timeout,
                timeoutValue: false,
                operationName,
                HashFingerprint(accessTokenHash));
            if (!result)
            {
                _logger.LogWarning(
                    "Active session cache write returned false during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                    operationName,
                    HashFingerprint(accessTokenHash));
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Active session cache write failed during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                operationName,
                HashFingerprint(accessTokenHash));
            return false;
        }
    }

    private async Task<bool> SafeRevokeActiveSession(IActiveUserCacheService activeUsers, string accessTokenHash, string operationName, TimeSpan timeout)
    {
        try
        {
            bool result = await WithTimeout(
                activeUsers.RevokeSession(accessTokenHash),
                timeout,
                timeoutValue: false,
                operationName,
                HashFingerprint(accessTokenHash));
            if (!result)
            {
                _logger.LogWarning(
                    "Active session cache revoke returned false during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                    operationName,
                    HashFingerprint(accessTokenHash));
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Active session cache revoke failed during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                operationName,
                HashFingerprint(accessTokenHash));
            return false;
        }
    }


    private async Task<ActiveSession?> TryLoadAuthoritativeSessionFromDatabase(
        ISessionRepo sessionRepo,
        string accessTokenHash,
        TimeSpan timeout)
    {
        try
        {
            Session? storedSession = await WithTimeout(
                sessionRepo.GetSession(accessTokenHash),
                timeout,
                timeoutValue: null,
                "active session database fallback lookup",
                HashFingerprint(accessTokenHash));

            if (storedSession == null || storedSession.sessionLifespan == null || storedSession.refreshes == null)
            {
                return null;
            }

            return new ActiveSession(
                accountId: storedSession.accountId,
                refreshToken: storedSession.refreshToken,
                refreshes: storedSession.refreshes.Value,
                createdOn: storedSession.createdOn,
                sessionLifespan: storedSession.sessionLifespan,
                accessExpiration: storedSession.accessExpiration,
                sessionExpiration: storedSession.sessionExpiration,
                cutOff: storedSession.cutOff,
                features: storedSession.features,
                securityStamp: storedSession.securityStamp,
                accountSecurityStamp: storedSession.accountSecurityStamp);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Active session database fallback lookup failed for token hash {AccessTokenHashFingerprint}.",
                HashFingerprint(accessTokenHash));
            return null;
        }
    }

    private async Task<T> WithTimeout<T>(
        Task<T> operation,
        TimeSpan timeout,
        T timeoutValue,
        string operationName,
        string accessTokenHashFingerprint)
    {
        TimeSpan effectiveTimeout = timeout <= TimeSpan.Zero ? TimeSpan.FromMilliseconds(1) : timeout;

        Task completed = await Task.WhenAny(operation, Task.Delay(effectiveTimeout));
        if (!ReferenceEquals(completed, operation))
        {
            _logger.LogWarning(
                "Timed out after {TimeoutMilliseconds}ms during {OperationName} for token hash {AccessTokenHashFingerprint}.",
                effectiveTimeout.TotalMilliseconds,
                operationName,
                accessTokenHashFingerprint);
            return timeoutValue;
        }

        return await operation;
    }

    private static string HashFingerprint(string accessTokenHash)
    {
        if (string.IsNullOrWhiteSpace(accessTokenHash))
        {
            return string.Empty;
        }

        return accessTokenHash.Length <= 12 ? accessTokenHash : accessTokenHash[..12];
    }

    private sealed record RefreshSessionResult(bool Succeeded, string? AccessToken = null, string? AccessTokenHash = null, ActiveSession? Session = null);

    private async Task<RefreshSessionResult> TryRefreshSession(
        string oldAccessTokenHash,
        ActiveSession currentSession,
        string webKey,
        IActiveUserCacheService activeUsers,
        IJsonWebTokenUtility jwtUtils,
        ISessionRepo sessionRepo,
        JWTSettings jwtSettings,
        SessionCacheFallbackSettings fallbackSettings)
    {
        Instant refreshedAt = SystemClock.Instance.GetCurrentInstant();
        Instant refreshedAccessExpiration = ResolveRefreshAccessExpiration(currentSession, jwtSettings, refreshedAt);
        if (refreshedAccessExpiration <= refreshedAt)
        {
            return new RefreshSessionResult(false);
        }

        ActiveSession refreshedSession = new(
            currentSession.accountId,
            RandomNumberGenerator.GetBytes(jwtSettings.RefreshTokenBytes),
            (short)(currentSession.refreshes + 1),
            currentSession.createdOn,
            currentSession.sessionLifespan,
            refreshedAccessExpiration,
            currentSession.sessionExpiration,
            currentSession.cutOff,
            currentSession.features,
            Guid.NewGuid(),
            currentSession.accountSecurityStamp);

        string refreshedAccessToken = jwtUtils.GenerateAccessToken(refreshedSession.refreshToken, webKey, JsonWebTokenPurpose.Active);
        string refreshedAccessTokenHash = AccessTokenHashUtility.Hash(refreshedAccessToken);

        SessionRotationResult? rotation;
        try
        {
            rotation = await WithTimeout(
                sessionRepo.RotateActiveSession(
                    currentSession.accountId,
                    oldAccessTokenHash,
                    refreshedAccessTokenHash,
                    refreshedSession.toSession()),
                fallbackSettings.DatabaseFallbackTimeout,
                timeoutValue: null,
                "active session database rotation",
                HashFingerprint(oldAccessTokenHash));
        }
        catch
        {
            return new RefreshSessionResult(false);
        }

        if (rotation?.Succeeded != true)
        {
            if (rotation?.Status == SessionRotationStatus.OldSessionMismatch)
            {
                await SafeRevokeActiveSession(activeUsers, oldAccessTokenHash, "stale old active session cache revoke after failed refresh rotation", fallbackSettings.CacheRevokeTimeout);
            }

            return new RefreshSessionResult(false);
        }

        TimeSpan cacheTtl = CalculateCacheTtl(refreshedSession, jwtSettings, refreshedAt);
        bool refreshedCacheSessionWritten = await SafeSetActiveSession(activeUsers, refreshedAccessTokenHash, refreshedSession, cacheTtl, "refreshed active session cache write", fallbackSettings.CacheWriteTimeout);
        if (!refreshedCacheSessionWritten)
        {
            // CORE-2: the DB rotation is authoritative. Redis write failure is only a cache miss;
            // return the refreshed token and allow a later request to hydrate the cache from DB.
        }

        await SafeRevokeActiveSession(activeUsers, oldAccessTokenHash, "old active session cache revoke after refresh rotation", fallbackSettings.CacheRevokeTimeout);
        return new RefreshSessionResult(true, refreshedAccessToken, refreshedAccessTokenHash, refreshedSession);
    }

    private static bool IsSessionHardExpired(ActiveSession session, Instant currentMoment)
    {
        return session.EffectiveSessionExpiration <= currentMoment;
    }

    private async Task TryRevokeExpiredSession(IActiveUserCacheService activeUsers, ISessionRepo sessionRepo, string accessTokenHash, SessionCacheFallbackSettings fallbackSettings)
    {
        await SafeRevokeActiveSession(activeUsers, accessTokenHash, "expired active session cache revoke", fallbackSettings.CacheRevokeTimeout);

        try
        {
            _ = await WithTimeout(
                sessionRepo.ExpireSession(accessTokenHash, null),
                fallbackSettings.DatabaseFallbackTimeout,
                timeoutValue: null,
                "expired active session database cleanup",
                HashFingerprint(accessTokenHash));
        }
        catch
        {
            // Database cleanup is best-effort from middleware; the request remains unauthenticated either way.
        }
    }

    private static TimeSpan CalculateCacheTtl(ActiveSession session, JWTSettings settings, Instant currentMoment)
    {
        Period configuredCachePeriod = BuildConfiguredCachePeriod(settings);

        Instant configuredCacheExpiration = currentMoment.Plus(configuredCachePeriod.ToDuration());
        Instant effectiveExpiration = Earliest(session.accessExpiration, configuredCacheExpiration);
        effectiveExpiration = Earliest(effectiveExpiration, session.EffectiveSessionExpiration);

        Duration ttl = effectiveExpiration - currentMoment;
        if (ttl <= Duration.Zero)
        {
            return TimeSpan.FromSeconds(1);
        }

        return ttl.ToTimeSpan();
    }

    private static Instant ResolveRefreshAccessExpiration(ActiveSession currentSession, JWTSettings settings, Instant refreshedAt)
    {
        Period requestedAccessPeriod = BuildShortAccessPeriod(settings);

        Instant requestedAccessExpiration = refreshedAt.Plus(requestedAccessPeriod.ToDuration());
        return Earliest(requestedAccessExpiration, currentSession.EffectiveSessionExpiration);
    }

    private static Period BuildConfiguredCachePeriod(JWTSettings settings)
    {
        return new PeriodBuilder
        {
            Days = settings.RefreshTokenAliveDays,
            Hours = settings.RefreshTokenAliveHours,
            Minutes = settings.RefreshTokenAliveMinutes
        }.Build();
    }

    private static Period BuildShortAccessPeriod(JWTSettings settings)
    {
        return new PeriodBuilder
        {
            Days = settings.RefreshTokenAliveDays_Short,
            Hours = settings.RefreshTokenAliveHours_Short,
            Minutes = settings.RefreshTokenAliveMinutes_Short
        }.Build();
    }

    private static Instant Earliest(Instant left, Instant right)
    {
        return left <= right ? left : right;
    }
}
