using System.Data.Common;

using Microsoft.Extensions.Options;

using StackExchange.Redis;

using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;

namespace treehammock.Rigging.Health;

public sealed record HealthDependencyResult(
    string name,
    string status,
    string? reasonCode = null,
    long? latencyMilliseconds = null)
{
    public bool Healthy => string.Equals(status, HealthDependencyStatus.Healthy, StringComparison.Ordinal);
}

public sealed record HealthDependencyReport(IReadOnlyList<HealthDependencyResult> dependencies)
{
    public bool Ready => dependencies.All(dependency => dependency.Healthy);

    public string Status => Ready ? HealthDependencyStatus.Ready : HealthDependencyStatus.NotReady;
}

public static class HealthDependencyStatus
{
    public const string Live = "live";
    public const string Ready = "ready";
    public const string NotReady = "not_ready";
    public const string Healthy = "healthy";
    public const string Unhealthy = "unhealthy";
}

public interface IHealthDependencyService
{
    Task<HealthDependencyReport> CheckAsync(CancellationToken cancellationToken = default);
}

public sealed class HealthDependencyService : IHealthDependencyService
{
    private readonly StorageContext _storageContext;
    private readonly Lazy<IConnectionMultiplexer> _activeSessionCacheConnection;
    private readonly Lazy<IConnectionMultiplexer> _twoFactorSessionCacheConnection;
    private readonly Lazy<IConnectionMultiplexer> _abuseCounterCacheConnection;

    public HealthDependencyService(
        StorageContext storageContext,
        IOptions<UserCacheSettings> activeSessionCacheSettings,
        IOptions<TwoFactorSessionCacheSettings> twoFactorSessionCacheSettings,
        IOptions<AbuseCounterCacheSettings> abuseCounterCacheSettings)
    {
        _storageContext = storageContext;
        _activeSessionCacheConnection = new Lazy<IConnectionMultiplexer>(() => ConnectionMultiplexer.Connect(
            ActiveUserCacheService.BuildConfiguration(activeSessionCacheSettings.Value)), LazyThreadSafetyMode.PublicationOnly);
        _twoFactorSessionCacheConnection = new Lazy<IConnectionMultiplexer>(() => ConnectionMultiplexer.Connect(
            TwoFactorSessionService.BuildConfiguration(twoFactorSessionCacheSettings.Value)), LazyThreadSafetyMode.PublicationOnly);
        _abuseCounterCacheConnection = new Lazy<IConnectionMultiplexer>(() => ConnectionMultiplexer.Connect(
            ActiveUserCacheService.BuildConfiguration(abuseCounterCacheSettings.Value)), LazyThreadSafetyMode.PublicationOnly);
    }

    public async Task<HealthDependencyReport> CheckAsync(CancellationToken cancellationToken = default)
    {
        var results = new List<HealthDependencyResult>
        {
            await CheckPostgreSqlAsync(cancellationToken),
            await CheckDragonflyAsync("dragonfly_active_sessions", _activeSessionCacheConnection, cancellationToken),
            await CheckDragonflyAsync("dragonfly_two_factor_sessions", _twoFactorSessionCacheConnection, cancellationToken),
            await CheckDragonflyAsync("dragonfly_abuse_counters", _abuseCounterCacheConnection, cancellationToken)
        };

        return new HealthDependencyReport(results);
    }

    private async Task<HealthDependencyResult> CheckPostgreSqlAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var measure = HealthCheckLatency.Start();
            await using DbConnection connection = await _storageContext.CreateConnection();
            await using DbCommand command = connection.CreateCommand();
            command.CommandText = "select 1";
            command.CommandTimeout = 2;

            object? result = await command.ExecuteScalarAsync(cancellationToken);
            if (Convert.ToInt32(result) == 1)
            {
                return Healthy("postgresql", measure.ElapsedMilliseconds);
            }

            return Unhealthy("postgresql", "unexpected_probe_result", measure.ElapsedMilliseconds);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            return Unhealthy("postgresql", "timeout", null);
        }
        catch (DbException)
        {
            return Unhealthy("postgresql", "database_unavailable", null);
        }
        catch (InvalidOperationException)
        {
            return Unhealthy("postgresql", "database_unavailable", null);
        }
    }

    private static async Task<HealthDependencyResult> CheckDragonflyAsync(
        string name,
        Lazy<IConnectionMultiplexer> connection,
        CancellationToken cancellationToken)
    {
        try
        {
            using var measure = HealthCheckLatency.Start();
            IConnectionMultiplexer multiplexer = connection.Value;
            IDatabase database = multiplexer.GetDatabase();
            _ = await database.PingAsync();
            cancellationToken.ThrowIfCancellationRequested();
            return Healthy(name, measure.ElapsedMilliseconds);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TimeoutException)
        {
            return Unhealthy(name, "timeout", null);
        }
        catch (RedisException)
        {
            return Unhealthy(name, "dragonfly_unavailable", null);
        }
        catch (InvalidOperationException)
        {
            return Unhealthy(name, "dragonfly_unavailable", null);
        }
    }

    private static HealthDependencyResult Healthy(string name, long latencyMilliseconds)
    {
        return new HealthDependencyResult(name, HealthDependencyStatus.Healthy, latencyMilliseconds: latencyMilliseconds);
    }

    private static HealthDependencyResult Unhealthy(string name, string reasonCode, long? latencyMilliseconds)
    {
        return new HealthDependencyResult(name, HealthDependencyStatus.Unhealthy, reasonCode, latencyMilliseconds);
    }

    private sealed class HealthCheckLatency : IDisposable
    {
        private readonly System.Diagnostics.Stopwatch _stopwatch = System.Diagnostics.Stopwatch.StartNew();

        private HealthCheckLatency()
        {
        }

        public long ElapsedMilliseconds => _stopwatch.ElapsedMilliseconds;

        public static HealthCheckLatency Start()
        {
            return new HealthCheckLatency();
        }

        public void Dispose()
        {
            _stopwatch.Stop();
        }
    }
}
