using Microsoft.Extensions.Options;

using StackExchange.Redis;

using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;

namespace treehammock.Rigging.Abuse;

public sealed class DragonflyAbuseCounterStore : IAbuseCounterStore
{
    private readonly AbuseControlSettings _abuseSettings;
    private readonly AbuseCounterCacheSettings _cacheSettings;
    private readonly ConfigurationOptions _configuration;
    private readonly Lazy<IConnectionMultiplexer> _lazyConnection;

    public DragonflyAbuseCounterStore(
        IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings)
        : this(cacheSettings, abuseSettings, null)
    {
    }

    public DragonflyAbuseCounterStore(
        IOptions<AbuseCounterCacheSettings> cacheSettings,
        IOptions<AbuseControlSettings> abuseSettings,
        IConnectionMultiplexer? connection)
    {
        _cacheSettings = cacheSettings.Value;
        _abuseSettings = abuseSettings.Value;
        _configuration = ActiveUserCacheService.BuildConfiguration(_cacheSettings);
        _lazyConnection = new Lazy<IConnectionMultiplexer>(() =>
        {
            if (connection is not null)
            {
                return connection;
            }

            return ConnectionMultiplexer.Connect(_configuration);
        });
    }

    public IConnectionMultiplexer Connection => _lazyConnection.Value;

    public IDatabase Database => Connection.GetDatabase();

    public async Task<CounterDecision> IncrementAsync(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        CancellationToken cancellationToken = default)
    {
        TimeSpan timeout = Timeout;

        try
        {
            CooldownDecision cooldown = await GetCooldownAsync(key, cancellationToken);
            if (cooldown.Active)
            {
                string reasonCode = cooldown.ReasonCode ?? AbuseReasonCodes.FailureCooldownActive;
                AbuseOperationalTelemetry.RecordPolicyDenied(key.Feature, key.Dimension, reasonCode);

                return new CounterDecision(
                    Allowed: false,
                    CurrentCount: limit.MaxAttempts + 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: cooldown.RetryAfter,
                    ReasonCode: reasonCode);
            }

            long count = await WithTimeout(
                Database.StringIncrementAsync(key.Value, 1L, CommandFlags.None),
                timeout,
                cancellationToken);

            if (count == 1)
            {
                _ = await WithTimeout(
                    Database.KeyExpireAsync(key.Value, limit.Window, CommandFlags.None),
                    timeout,
                    cancellationToken);
            }

            if (count <= limit.MaxAttempts)
            {
                AbuseOperationalTelemetry.RecordPolicyAllowed(key.Feature, key.Dimension);

                return new CounterDecision(
                    Allowed: true,
                    CurrentCount: CheckedCount(count),
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: null,
                    ReasonCode: null);
            }

            TimeSpan? retryAfter = await StartCooldownOrGetRetryAfterAsync(key, limit, timeout, cancellationToken);
            AbuseOperationalTelemetry.RecordPolicyDenied(key.Feature, key.Dimension, AbuseReasonCodes.CounterLimitExceeded);
            if (limit.Cooldown.HasValue && limit.Cooldown.Value > TimeSpan.Zero)
            {
                AbuseOperationalTelemetry.RecordCooldownStarted(key.Feature, key.Dimension, AbuseReasonCodes.CounterLimitExceeded);
            }

            return new CounterDecision(
                Allowed: false,
                CurrentCount: CheckedCount(count),
                Limit: limit.MaxAttempts,
                Window: limit.Window,
                RetryAfter: retryAfter,
                ReasonCode: AbuseReasonCodes.CounterLimitExceeded);
        }
        catch (TimeoutException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreTimeout, "increment");
        }
        catch (RedisException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreUnavailable, "increment");
        }
        catch (ObjectDisposedException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreUnavailable, "increment");
        }
        catch (InvalidOperationException)
        {
            return CounterStoreUnavailableDecision(key, limit, AbuseReasonCodes.CounterStoreUnavailable, "increment");
        }
    }

    public async Task ResetAsync(
        AbuseCounterKey key,
        CancellationToken cancellationToken = default)
    {
        TimeSpan timeout = Timeout;

        try
        {
            _ = await WithTimeout(Database.KeyDeleteAsync(key.Value, CommandFlags.None), timeout, cancellationToken);
            _ = await WithTimeout(Database.KeyDeleteAsync(key.CooldownValue, CommandFlags.None), timeout, cancellationToken);
        }
        catch (TimeoutException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreTimeout);
        }
        catch (RedisException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreUnavailable);
        }
        catch (ObjectDisposedException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreUnavailable);
        }
        catch (InvalidOperationException)
        {
            AbuseOperationalTelemetry.RecordCounterStoreFailure("reset", AbuseReasonCodes.CounterStoreUnavailable);
        }
    }

    public async Task<CooldownDecision> GetCooldownAsync(
        AbuseCounterKey key,
        CancellationToken cancellationToken = default)
    {
        TimeSpan timeout = Timeout;

        try
        {
            TimeSpan? ttl = await WithTimeout(
                Database.KeyTimeToLiveAsync(key.CooldownValue, CommandFlags.None),
                timeout,
                cancellationToken);

            if (ttl is null || ttl <= TimeSpan.Zero)
            {
                return new CooldownDecision(false, null, null);
            }

            return new CooldownDecision(true, ttl, AbuseReasonCodes.FailureCooldownActive);
        }
        catch (TimeoutException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreTimeout, "cooldown_lookup");
        }
        catch (RedisException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreUnavailable, "cooldown_lookup");
        }
        catch (ObjectDisposedException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreUnavailable, "cooldown_lookup");
        }
        catch (InvalidOperationException)
        {
            return CounterStoreUnavailableCooldown(AbuseReasonCodes.CounterStoreUnavailable, "cooldown_lookup");
        }
    }

    private TimeSpan Timeout => TimeSpan.FromMilliseconds(_abuseSettings.DragonflyTimeoutMilliseconds);

    private bool AllowWhenCounterStoreUnavailable =>
        _abuseSettings.CounterFailureMode == AbuseCounterFailureMode.AllowWhenPostgreSqlAuthoritativeStateExists;

    private CounterDecision CounterStoreUnavailableDecision(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        string reasonCode,
        string operation)
    {
        AbuseOperationalTelemetry.RecordCounterStoreFailure(operation, reasonCode);
        if (!AllowWhenCounterStoreUnavailable)
        {
            AbuseOperationalTelemetry.RecordPolicyDenied(key.Feature, key.Dimension, reasonCode);
        }

        return new CounterDecision(
            Allowed: AllowWhenCounterStoreUnavailable,
            CurrentCount: 0,
            Limit: limit.MaxAttempts,
            Window: limit.Window,
            RetryAfter: null,
            ReasonCode: reasonCode);
    }

    private CooldownDecision CounterStoreUnavailableCooldown(string reasonCode, string operation)
    {
        AbuseOperationalTelemetry.RecordCounterStoreFailure(operation, reasonCode);

        return new CooldownDecision(
            Active: !AllowWhenCounterStoreUnavailable,
            RetryAfter: null,
            ReasonCode: reasonCode);
    }

    private async Task<TimeSpan?> StartCooldownOrGetRetryAfterAsync(
        AbuseCounterKey key,
        AbuseCounterLimit limit,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (limit.Cooldown.HasValue && limit.Cooldown.Value > TimeSpan.Zero)
        {
            _ = await WithTimeout(
                Database.StringSetAsync(
                    key.CooldownValue,
                    AbuseReasonCodes.FailureCooldownActive,
                    limit.Cooldown,
                    When.NotExists,
                    CommandFlags.None),
                timeout,
                cancellationToken);

            TimeSpan? cooldownTtl = await WithTimeout(
                Database.KeyTimeToLiveAsync(key.CooldownValue, CommandFlags.None),
                timeout,
                cancellationToken);

            return cooldownTtl.HasValue && cooldownTtl.Value > TimeSpan.Zero ? cooldownTtl : limit.Cooldown;
        }

        TimeSpan? counterTtl = await WithTimeout(
            Database.KeyTimeToLiveAsync(key.Value, CommandFlags.None),
            timeout,
            cancellationToken);

        return counterTtl.HasValue && counterTtl.Value > TimeSpan.Zero ? counterTtl : limit.Window;
    }

    private static int CheckedCount(long count)
    {
        return count > int.MaxValue ? int.MaxValue : (int)count;
    }

    private static async Task<T> WithTimeout<T>(Task<T> task, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            return await task.WaitAsync(timeout, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException("Dragonfly abuse counter operation timed out.");
        }
    }
}
