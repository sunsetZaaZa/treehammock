using Microsoft.Extensions.Options;

using Newtonsoft.Json;
using StackExchange.Redis;

using treehammock.DataLayer.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;

namespace treehammock.Rigging.Cache;

public interface ITwoFactorSessionService
{
    public Task<TwoFactorSession?> GetSession(string hashedAccessToken);
    public Task<bool?> SetSession(string hashedAccessToken, TwoFactorSession session, TimeSpan expire, CommandFlags flags = CommandFlags.PreferMaster);
    public Task<bool> RevokeSession(string hashedAccessToken);
    public Task<bool> AdjustExpiration(string newHashedAccessToken, TimeSpan expire);
}

// Should use the pending two-factor Redis database, usually index one / 1.
public class TwoFactorSessionService : ITwoFactorSessionService
{
    protected TwoFactorSessionCacheSettings _config;

    private readonly ConfigurationOptions _configuration;
    private Lazy<IConnectionMultiplexer> _lazyConnection;

    public TwoFactorSessionService(IOptions<TwoFactorSessionCacheSettings> config)
        : this(config, null)
    {
    }

    public TwoFactorSessionService(IOptions<TwoFactorSessionCacheSettings> config, IConnectionMultiplexer? connection)
    {
        this._config = config.Value;
        _configuration = BuildConfiguration(_config);

        _lazyConnection = new Lazy<IConnectionMultiplexer>(() =>
        {
            if (connection is not null)
            {
                return connection;
            }

            ConnectionMultiplexer redis = ConnectionMultiplexer.Connect(_configuration);
            //redis.ErrorMessage += _Connection_ErrorMessage;
            //redis.InternalError += _Connection_InternalError;
            //redis.ConnectionFailed += _Connection_ConnectionFailed;
            //redis.ConnectionRestored += _Connection_ConnectionRestored;
            return redis;
        });
    }

    public static ConfigurationOptions BuildConfiguration(TwoFactorSessionCacheSettings config)
    {
        return new ConfigurationOptions()
        {
            EndPoints = { { config.servers, config.port }, },
            AllowAdmin = config.allowAdmin,
            Password = config.password,
            ClientName = config.clientName,
            ReconnectRetryPolicy = new LinearRetry((int)config.reconnectRetryPolicy),
            AbortOnConnectFail = config.abortOnConnectFail,
            ConnectTimeout = config.connectTimeoutMilliseconds,
            AsyncTimeout = config.asyncTimeoutMilliseconds,
            SyncTimeout = config.syncTimeoutMilliseconds,
            ConnectRetry = config.connectRetry,
            DefaultDatabase = config.database
        };
    }

    public IConnectionMultiplexer _connection { get { return _lazyConnection.Value; } }

    public IDatabase _database => _connection.GetDatabase();

    public async Task<TwoFactorSession?> GetSession(string hashedAccessToken)
    {
        var redisResult = await _database.StringGetAsync(hashedAccessToken);
        if (redisResult.IsNullOrEmpty)
        {
            return null;
        }

        try
        {
            return CacheJsonSettings.Deserialize<TwoFactorSession>(redisResult.ToString());
        }
        catch (JsonException exception)
        {
            throw new StalePendingTwoFactorCachePayloadException("Pending two-factor cache payload is stale or malformed.", exception);
        }
        catch (ArgumentException exception)
        {
            throw new StalePendingTwoFactorCachePayloadException("Pending two-factor cache payload is missing required security fields.", exception);
        }
    }

    public async Task<bool?> SetSession(string hashedAccessToken, TwoFactorSession session, TimeSpan expire, CommandFlags flag = CommandFlags.PreferMaster)
    {
        _ = AccountSecurityStampGuard.Require(session.accountSecurityStamp);
        var result = await _database.StringSetAsync(hashedAccessToken, CacheJsonSettings.Serialize(session), expire, When.Always, flag);
        return result;
    }

    public async Task<bool> RevokeSession(string hashedAccessToken)
    {
        bool deleted = await _database.KeyDeleteAsync(hashedAccessToken);
        if (deleted)
        {
            return true;
        }

        bool stillExists = await _database.KeyExistsAsync(hashedAccessToken);
        return !stillExists;
    }

    public async Task<bool> AdjustExpiration(string hashedAccessToken, TimeSpan expire)
    {
        var result = await _database.KeyExpireAsync(hashedAccessToken, expire);
        return result;
    }
}
