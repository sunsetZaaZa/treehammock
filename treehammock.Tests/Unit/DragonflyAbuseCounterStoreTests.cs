using Microsoft.Extensions.Options;

using NSubstitute;
using Shouldly;
using StackExchange.Redis;

using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;

namespace treehammock.Tests.Unit;

public class DragonflyAbuseCounterStoreTests
{
    [Fact]
    public async Task Increment_creates_counter_window_on_first_attempt()
    {
        var database = Substitute.For<IDatabase>();
        var store = CreateStore(database);
        var key = Key();
        var limit = Limit();

        database.KeyTimeToLiveAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult<TimeSpan?>(null));
        database.StringIncrementAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.Value), Arg.Any<long>(), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(1L));
        database.KeyExpireAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.Value), limit.Window, Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(true));

        CounterDecision decision = await store.IncrementAsync(key, limit);

        decision.Allowed.ShouldBeTrue();
        decision.CurrentCount.ShouldBe(1);
        decision.Limit.ShouldBe(limit.MaxAttempts);
        decision.ReasonCode.ShouldBeNull();
        database.ReceivedCalls().Any(call =>
            call.GetMethodInfo().Name == nameof(IDatabase.KeyExpireAsync) &&
            call.GetArguments()[0]?.ToString() == key.Value &&
            Equals(call.GetArguments()[1], limit.Window)).ShouldBeTrue();
    }

    [Fact]
    public async Task Increment_denies_and_starts_cooldown_when_limit_is_exceeded()
    {
        var database = Substitute.For<IDatabase>();
        var store = CreateStore(database);
        var key = Key();
        var cooldown = TimeSpan.FromMinutes(15);
        var limit = Limit(cooldown);

        database.KeyTimeToLiveAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult<TimeSpan?>(null), Task.FromResult<TimeSpan?>(cooldown));
        database.StringIncrementAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.Value), Arg.Any<long>(), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(6L));
        database.StringSetAsync(
                Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue),
                Arg.Is<RedisValue>(value => value.ToString() == AbuseReasonCodes.FailureCooldownActive),
                cooldown,
                When.NotExists,
                Arg.Any<CommandFlags>())
            .Returns(Task.FromResult(true));

        CounterDecision decision = await store.IncrementAsync(key, limit);

        decision.Allowed.ShouldBeFalse();
        decision.CurrentCount.ShouldBe(6);
        decision.Limit.ShouldBe(limit.MaxAttempts);
        decision.RetryAfter.ShouldBe(cooldown);
        decision.ReasonCode.ShouldBe(AbuseReasonCodes.CounterLimitExceeded);
        database.ReceivedCalls().Any(call =>
            call.GetMethodInfo().Name == nameof(IDatabase.StringSetAsync) &&
            call.GetArguments()[0]?.ToString() == key.CooldownValue &&
            Equals(call.GetArguments()[2], cooldown) &&
            Equals(call.GetArguments()[3], When.NotExists)).ShouldBeTrue();
    }

    [Fact]
    public async Task Increment_denies_active_cooldown_without_incrementing_counter()
    {
        var database = Substitute.For<IDatabase>();
        var store = CreateStore(database);
        var key = Key();
        var limit = Limit(TimeSpan.FromMinutes(15));
        var retryAfter = TimeSpan.FromMinutes(9);

        database.KeyTimeToLiveAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult<TimeSpan?>(retryAfter));

        CounterDecision decision = await store.IncrementAsync(key, limit);

        decision.Allowed.ShouldBeFalse();
        decision.RetryAfter.ShouldBe(retryAfter);
        decision.ReasonCode.ShouldBe(AbuseReasonCodes.FailureCooldownActive);
        _ = database.DidNotReceive().StringIncrementAsync(Arg.Any<RedisKey>(), Arg.Any<long>(), Arg.Any<CommandFlags>());
    }

    [Fact]
    public async Task GetCooldown_returns_active_status_from_cooldown_ttl()
    {
        var database = Substitute.For<IDatabase>();
        var store = CreateStore(database);
        var key = Key();
        var retryAfter = TimeSpan.FromSeconds(45);

        database.KeyTimeToLiveAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult<TimeSpan?>(retryAfter));

        CooldownDecision decision = await store.GetCooldownAsync(key);

        decision.Active.ShouldBeTrue();
        decision.RetryAfter.ShouldBe(retryAfter);
        decision.ReasonCode.ShouldBe(AbuseReasonCodes.FailureCooldownActive);
    }

    [Fact]
    public async Task Reset_removes_counter_and_cooldown_keys()
    {
        var database = Substitute.For<IDatabase>();
        var store = CreateStore(database);
        var key = Key();

        database.KeyDeleteAsync(Arg.Any<RedisKey>(), Arg.Any<CommandFlags>()).Returns(Task.FromResult(true));

        await store.ResetAsync(key);

        await database.Received(1).KeyDeleteAsync(
            Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.Value),
            Arg.Any<CommandFlags>());
        await database.Received(1).KeyDeleteAsync(
            Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue),
            Arg.Any<CommandFlags>());
    }

    [Fact]
    public async Task Increment_fails_closed_when_counter_store_is_unavailable_by_default()
    {
        var database = Substitute.For<IDatabase>();
        var store = CreateStore(database);
        var key = Key();
        var limit = Limit();

        database.KeyTimeToLiveAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue), Arg.Any<CommandFlags>())
            .Returns(_ => Task.FromException<TimeSpan?>(new InvalidOperationException("dragonfly unavailable")));

        CounterDecision decision = await store.IncrementAsync(key, limit);

        decision.Allowed.ShouldBeFalse();
        decision.ReasonCode.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
    }

    [Fact]
    public async Task Increment_can_allow_when_configured_for_postgresql_authoritative_fallback()
    {
        var database = Substitute.For<IDatabase>();
        var store = CreateStore(
            database,
            new AbuseControlSettings
            {
                CounterFailureMode = AbuseCounterFailureMode.AllowWhenPostgreSqlAuthoritativeStateExists
            });
        var key = Key();
        var limit = Limit();

        database.KeyTimeToLiveAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.CooldownValue), Arg.Any<CommandFlags>())
            .Returns(Task.FromResult<TimeSpan?>(null));
        database.StringIncrementAsync(Arg.Is<RedisKey>(redisKey => redisKey.ToString() == key.Value), Arg.Any<long>(), Arg.Any<CommandFlags>())
            .Returns(_ => Task.FromException<long>(new InvalidOperationException("dragonfly unavailable")));

        CounterDecision decision = await store.IncrementAsync(key, limit);

        decision.Allowed.ShouldBeTrue();
        decision.ReasonCode.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
    }

    [Fact]
    public void Abuse_counter_cache_settings_builds_isolated_dragonfly_configuration()
    {
        var settings = CacheSettings(database: 2);

        ConfigurationOptions configuration = treehammock.Rigging.Cache.ActiveUserCacheService.BuildConfiguration(settings);

        configuration.DefaultDatabase.ShouldBe(2);
        configuration.ClientName.ShouldBe("treehammock-tests-abuse-counters");
        configuration.ConnectTimeout.ShouldBe(1000);
        configuration.AsyncTimeout.ShouldBe(1000);
        configuration.SyncTimeout.ShouldBe(1000);
        configuration.ConnectRetry.ShouldBe(1);
    }

    private static DragonflyAbuseCounterStore CreateStore(
        IDatabase database,
        AbuseControlSettings? settings = null)
    {
        var connection = Substitute.For<IConnectionMultiplexer>();
        connection.GetDatabase(Arg.Any<int>(), Arg.Any<object?>()).Returns(database);

        return new DragonflyAbuseCounterStore(
            Options.Create(CacheSettings()),
            Options.Create(settings ?? new AbuseControlSettings()),
            connection);
    }

    private static AbuseCounterCacheSettings CacheSettings(int database = 2)
    {
        return new AbuseCounterCacheSettings
        {
            servers = "localhost",
            port = 6379,
            database = database,
            clientName = "treehammock-tests-abuse-counters",
            allowAdmin = false,
            reconnectRetryPolicy = 5000,
            abortOnConnectFail = false,
            password = string.Empty,
            connectTimeoutMilliseconds = 1000,
            asyncTimeoutMilliseconds = 1000,
            syncTimeoutMilliseconds = 1000,
            connectRetry = 1
        };
    }

    private static AbuseCounterKey Key()
    {
        return new AbuseCounterKey(
            AbuseFeature.TwoFactorChallenge,
            AbuseCounterDimension.Challenge,
            "challenge-123");
    }

    private static AbuseCounterLimit Limit(TimeSpan? cooldown = null)
    {
        return new AbuseCounterLimit(
            maxAttempts: 5,
            window: TimeSpan.FromMinutes(10),
            cooldown: cooldown);
    }
}
