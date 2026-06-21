using NodaTime;
using StackExchange.Redis;

using treehammock.DataLayer.Cache;
using treehammock.Repos;

namespace treehammock.Rigging.Cache;

public interface IPasswordResetSessionService
{
    public Task<PasswordResetSession?> GetSession(string resetAccessTokenHash);
    public Task<bool?> SetSession(string resetAccessTokenHash, PasswordResetSession session, TimeSpan expire, CommandFlags flags = CommandFlags.PreferMaster);
    public Task<bool> RevokeSession(string resetAccessTokenHash);
}

/// <summary>
/// Persists pending password-reset 2FA sessions in PostgreSQL.
/// The service intentionally keeps the cache-shaped contract introduced in PR Reset-5
/// so controllers and orchestration code do not care whether the backing store is Redis
/// or durable SQL state.
/// </summary>
public sealed class PasswordResetSessionService : IPasswordResetSessionService
{
    private readonly IPasswordResetRepo _passwordResetRepo;

    public PasswordResetSessionService(IPasswordResetRepo passwordResetRepo)
    {
        _passwordResetRepo = passwordResetRepo;
    }

    public async Task<PasswordResetSession?> GetSession(string resetAccessTokenHash)
    {
        return await _passwordResetRepo.GetPendingPasswordResetSessionAsync(
            NormalizeHash(resetAccessTokenHash),
            CancellationToken.None);
    }

    public async Task<bool?> SetSession(
        string resetAccessTokenHash,
        PasswordResetSession session,
        TimeSpan expire,
        CommandFlags flags = CommandFlags.PreferMaster)
    {
        ArgumentNullException.ThrowIfNull(session);

        string normalizedHash = NormalizeHash(resetAccessTokenHash);
        if (!string.Equals(session.resetAccessTokenHash, normalizedHash, StringComparison.Ordinal))
        {
            throw new ArgumentException("The password reset session hash must match the SQL row key hash.", nameof(session));
        }

        // The previous cache implementation used expire as the Redis TTL. SQL stores the absolute
        // session expiration on the session itself, so this argument remains part of the public seam
        // but no longer controls persistence directly.
        _ = expire;
        _ = flags;

        PasswordResetSessionCommandResult? result = await _passwordResetRepo.UpsertPendingPasswordResetSessionAsync(
            session,
            CancellationToken.None);

        return result?.Result;
    }

    public async Task<bool> RevokeSession(string resetAccessTokenHash)
    {
        PasswordResetSessionCommandResult? result = await _passwordResetRepo.RevokePendingPasswordResetSessionAsync(
            NormalizeHash(resetAccessTokenHash),
            SystemClock.Instance.GetCurrentInstant(),
            "PASSWORD_RESET_SESSION_REVOKED",
            CancellationToken.None);

        return result?.Result == true || string.Equals(result?.Code, "PASSWORD_RESET_SESSION_NOT_FOUND", StringComparison.Ordinal);
    }

    private static string NormalizeHash(string resetAccessTokenHash)
    {
        if (string.IsNullOrWhiteSpace(resetAccessTokenHash))
        {
            throw new ArgumentException("Password reset access-token hash is required.", nameof(resetAccessTokenHash));
        }

        return resetAccessTokenHash.Trim();
    }
}
