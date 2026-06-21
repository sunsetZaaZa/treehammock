using System.Security.Cryptography;
using System.Text;

using Microsoft.Extensions.Options;

using StackExchange.Redis;

using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Replay;

public static class AuthenticatedMutationIdempotencyConstants
{
    public const string HeaderName = "Idempotency-Key";
    public const string MissingRequiredKeyCode = "IDEMPOTENCY_KEY_REQUIRED";
    public const string InvalidKeyCode = "IDEMPOTENCY_KEY_INVALID";
    public const string ReplayInProgressCode = "IDEMPOTENCY_REPLAY_IN_PROGRESS";
    public const string StoreUnavailableCode = "IDEMPOTENCY_STORE_UNAVAILABLE";
}

public enum AuthenticatedMutationIdempotencyStatus
{
    NotApplied = 0,
    Started = 1,
    ReplayCompleted = 2,
    ReplayInProgress = 3,
    InvalidKey = 4,
    StoreUnavailable = 5,
    MissingRequiredKey = 6
}

public sealed record AuthenticatedMutationIdempotencyRequest(
    Guid AccountId,
    string Method,
    string Route,
    string? IdempotencyKey,
    bool RequireKey = false);

public sealed record AuthenticatedMutationIdempotencyReservation(string CacheKey, string ReservationToken);

public sealed record AuthenticatedMutationIdempotencyStoredResult(int StatusCode, string Code);

public sealed record AuthenticatedMutationIdempotencyBeginResult(
    AuthenticatedMutationIdempotencyStatus Status,
    AuthenticatedMutationIdempotencyReservation? Reservation = null,
    AuthenticatedMutationIdempotencyStoredResult? StoredResult = null,
    string? ReasonCode = null)
{
    public bool Started => Status == AuthenticatedMutationIdempotencyStatus.Started;
    public bool NotApplied => Status == AuthenticatedMutationIdempotencyStatus.NotApplied;

    public static AuthenticatedMutationIdempotencyBeginResult NotAppliedResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(AuthenticatedMutationIdempotencyStatus.NotApplied);
    }

    public static AuthenticatedMutationIdempotencyBeginResult StartedResult(AuthenticatedMutationIdempotencyReservation reservation)
    {
        return new AuthenticatedMutationIdempotencyBeginResult(AuthenticatedMutationIdempotencyStatus.Started, reservation);
    }

    public static AuthenticatedMutationIdempotencyBeginResult ReplayCompletedResult(AuthenticatedMutationIdempotencyStoredResult result)
    {
        return new AuthenticatedMutationIdempotencyBeginResult(AuthenticatedMutationIdempotencyStatus.ReplayCompleted, StoredResult: result);
    }

    public static AuthenticatedMutationIdempotencyBeginResult ReplayInProgressResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.ReplayInProgress,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.ReplayInProgressCode);
    }

    public static AuthenticatedMutationIdempotencyBeginResult MissingRequiredKeyResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.MissingRequiredKey,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode);
    }

    public static AuthenticatedMutationIdempotencyBeginResult InvalidKeyResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.InvalidKey,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.InvalidKeyCode);
    }

    public static AuthenticatedMutationIdempotencyBeginResult StoreUnavailableResult()
    {
        return new AuthenticatedMutationIdempotencyBeginResult(
            AuthenticatedMutationIdempotencyStatus.StoreUnavailable,
            ReasonCode: AuthenticatedMutationIdempotencyConstants.StoreUnavailableCode);
    }
}

public interface IAuthenticatedMutationIdempotencyService
{
    Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request,
        CancellationToken cancellationToken = default);

    Task CompleteAsync(
        AuthenticatedMutationIdempotencyReservation? reservation,
        int statusCode,
        string code,
        CancellationToken cancellationToken = default);
}

public sealed class NoOpAuthenticatedMutationIdempotencyService : IAuthenticatedMutationIdempotencyService
{
    public static NoOpAuthenticatedMutationIdempotencyService Instance { get; } = new();

    private NoOpAuthenticatedMutationIdempotencyService()
    {
    }

    public Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(AuthenticatedMutationIdempotencyBeginResult.NotAppliedResult());
    }

    public Task CompleteAsync(
        AuthenticatedMutationIdempotencyReservation? reservation,
        int statusCode,
        string code,
        CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}

public sealed class DragonflyAuthenticatedMutationIdempotencyService : IAuthenticatedMutationIdempotencyService
{
    private const string ReservedPrefix = "reserved";
    private const string CompletedPrefix = "completed";

    private readonly AbuseCounterCacheSettings _cacheSettings;
    private readonly AuthenticatedMutationIdempotencySettings _settings;
    private readonly ConfigurationOptions _configuration;
    private readonly Lazy<IConnectionMultiplexer> _lazyConnection;

    public DragonflyAuthenticatedMutationIdempotencyService(
        IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings)
        : this(cacheSettings, abuseSettings, null)
    {
    }

    public DragonflyAuthenticatedMutationIdempotencyService(
        IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings,
        IConnectionMultiplexer? connection)
    {
        _cacheSettings = cacheSettings.Value;
        _settings = abuseSettings.Value.AuthenticatedMutationIdempotency;
        _configuration = ActiveUserCacheService.BuildConfiguration(_cacheSettings);
        _lazyConnection = new Lazy<IConnectionMultiplexer>(() => connection ?? ConnectionMultiplexer.Connect(_configuration));
    }

    public IConnectionMultiplexer Connection => _lazyConnection.Value;

    public IDatabase Database => Connection.GetDatabase();

    public async Task<AuthenticatedMutationIdempotencyBeginResult> BeginAsync(
        AuthenticatedMutationIdempotencyRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_settings.Enabled)
        {
            return AuthenticatedMutationIdempotencyBeginResult.NotAppliedResult();
        }

        if (request.IdempotencyKey is null)
        {
            return request.RequireKey
                ? AuthenticatedMutationIdempotencyBeginResult.MissingRequiredKeyResult()
                : AuthenticatedMutationIdempotencyBeginResult.NotAppliedResult();
        }

        string? normalizedClientKey = NormalizeClientKey(request.IdempotencyKey, _settings.MinKeyLength, _settings.MaxKeyLength);
        if (normalizedClientKey is null)
        {
            return AuthenticatedMutationIdempotencyBeginResult.InvalidKeyResult();
        }

        string cacheKey = BuildCacheKey(
            request.AccountId,
            request.Method,
            request.Route,
            normalizedClientKey);
        string reservationToken = Guid.NewGuid().ToString("N");
        string reservedValue = $"{ReservedPrefix}|{reservationToken}";

        try
        {
            bool reserved = await WithTimeout(
                Database.StringSetAsync(
                    cacheKey,
                    reservedValue,
                    TimeSpan.FromSeconds(_settings.InProgressTtlSeconds),
                    When.NotExists),
                cancellationToken);

            if (reserved)
            {
                return AuthenticatedMutationIdempotencyBeginResult.StartedResult(
                    new AuthenticatedMutationIdempotencyReservation(cacheKey, reservationToken));
            }

            RedisValue existing = await WithTimeout(Database.StringGetAsync(cacheKey), cancellationToken);
            if (!existing.HasValue)
            {
                return AuthenticatedMutationIdempotencyBeginResult.ReplayInProgressResult();
            }

            string existingValue = existing.ToString();
            if (TryParseCompleted(existingValue, out AuthenticatedMutationIdempotencyStoredResult? storedResult))
            {
                return AuthenticatedMutationIdempotencyBeginResult.ReplayCompletedResult(storedResult!);
            }

            return AuthenticatedMutationIdempotencyBeginResult.ReplayInProgressResult();
        }
        catch (TimeoutException)
        {
            return AuthenticatedMutationIdempotencyBeginResult.StoreUnavailableResult();
        }
        catch (RedisException)
        {
            return AuthenticatedMutationIdempotencyBeginResult.StoreUnavailableResult();
        }
        catch (ObjectDisposedException)
        {
            return AuthenticatedMutationIdempotencyBeginResult.StoreUnavailableResult();
        }
        catch (InvalidOperationException)
        {
            return AuthenticatedMutationIdempotencyBeginResult.StoreUnavailableResult();
        }
    }

    public async Task CompleteAsync(
        AuthenticatedMutationIdempotencyReservation? reservation,
        int statusCode,
        string code,
        CancellationToken cancellationToken = default)
    {
        if (!_settings.Enabled || reservation is null || string.IsNullOrWhiteSpace(code))
        {
            return;
        }

        string completedValue = $"{CompletedPrefix}|{statusCode}|{NormalizeStoredCode(code)}";

        try
        {
            RedisValue current = await WithTimeout(Database.StringGetAsync(reservation.CacheKey), cancellationToken);
            if (!current.HasValue || !string.Equals(current.ToString(), $"{ReservedPrefix}|{reservation.ReservationToken}", StringComparison.Ordinal))
            {
                return;
            }

            _ = await WithTimeout(
                Database.StringSetAsync(
                    reservation.CacheKey,
                    completedValue,
                    TimeSpan.FromSeconds(_settings.CompletedTtlSeconds),
                    When.Always),
                cancellationToken);
        }
        catch (TimeoutException)
        {
        }
        catch (RedisException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }

    public static string BuildCacheKey(Guid accountId, string method, string route, string normalizedClientKey)
    {
        string methodSegment = NormalizeRouteSegment(method, nameof(method));
        string routeSegment = NormalizeRouteSegment(route, nameof(route));
        string keyFingerprint = Fingerprint(normalizedClientKey);

        return $"idempotency:authmutation:{accountId:N}:{methodSegment}:{routeSegment}:{keyFingerprint}";
    }

    public static string? NormalizeClientKey(string? value, int minLength, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string normalized = value.Trim();
        if (normalized.Length < minLength || normalized.Length > maxLength)
        {
            return null;
        }

        foreach (char c in normalized)
        {
            bool safe = c is >= 'a' and <= 'z'
                || c is >= 'A' and <= 'Z'
                || c is >= '0' and <= '9'
                || c == '_'
                || c == '-'
                || c == '.'
                || c == ':';

            if (!safe)
            {
                return null;
            }
        }

        return normalized;
    }

    private static bool TryParseCompleted(string value, out AuthenticatedMutationIdempotencyStoredResult? result)
    {
        result = null;
        string[] parts = value.Split('|', 3);
        if (parts.Length != 3 || !string.Equals(parts[0], CompletedPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        if (!int.TryParse(parts[1], out int statusCode) || statusCode < 100 || statusCode > 599)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(parts[2]))
        {
            return false;
        }

        result = new AuthenticatedMutationIdempotencyStoredResult(statusCode, parts[2]);
        return true;
    }

    private static string NormalizeStoredCode(string code)
    {
        string trimmed = code.Trim().ToUpperInvariant();
        var builder = new StringBuilder(trimmed.Length);
        foreach (char c in trimmed)
        {
            builder.Append(char.IsLetterOrDigit(c) || c == '_' || c == '-' ? c : '_');
        }

        return builder.ToString();
    }

    private static string NormalizeRouteSegment(string value, string argumentName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Idempotency route segments are required.", argumentName);
        }

        string normalized = value.Trim().ToLowerInvariant().Replace('/', '-');
        var builder = new StringBuilder(normalized.Length);
        foreach (char c in normalized)
        {
            builder.Append(char.IsLetterOrDigit(c) || c == '-' || c == '_' ? c : '-');
        }

        string result = builder.ToString().Trim('-');
        if (string.IsNullOrWhiteSpace(result))
        {
            throw new ArgumentException("Idempotency route segments must contain at least one safe character.", argumentName);
        }

        return result;
    }

    private static string Fingerprint(string value)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes).ToLowerInvariant()[..32];
    }

    private async Task<T> WithTimeout<T>(Task<T> operation, CancellationToken cancellationToken)
    {
        Task delay = Task.Delay(TimeSpan.FromMilliseconds(_settings.TimeoutMilliseconds), cancellationToken);
        Task completed = await Task.WhenAny(operation, delay);
        if (completed == delay)
        {
            throw new TimeoutException("Authenticated mutation idempotency operation timed out.");
        }

        return await operation;
    }
}
