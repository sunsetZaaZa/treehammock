using Npgsql;
using Shouldly;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class ActivationProcedureContractTests
{
    [Fact]
    public async Task Activation_procedures_return_distinct_result_codes_for_stale_stamp_expired_and_wrong_code()
    {
        if (!DeferredSqlProcedureContractSettings.ShouldRun())
        {
            throw new InvalidOperationException(DeferredSqlProcedureContractSettings.SkipReason);
        }

        string connectionString = DeferredSqlProcedureContractSettings.ConnectionString!;
        await using var connection = new NpgsqlConnection(connectionString);
        await connection.OpenAsync();

        string schema = "activation_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(connection, $"create schema {schema};");
            await ExecuteAsync(connection, $"set search_path to {schema};");
            await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));

            Guid accountId = Guid.NewGuid();
            byte[] hashedPassword = Enumerable.Repeat((byte)1, 128).ToArray();
            byte[] saltOne = Enumerable.Repeat((byte)2, 64).ToArray();
            byte[] siv = Enumerable.Repeat((byte)3, 32).ToArray();
            byte[] nonce = Enumerable.Repeat((byte)4, 16).ToArray();

            await ExecuteAsync(
                connection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'reader@example.com', 'reader', @hashedPassword, 'web-key-' || gen_random_uuid()::text, @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", accountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid accountSecurityStamp = await QueryGuidAsync(
                connection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            (bool placed, string placedCode, short? placedStatus) = await QueryActivationCommandAsync(
                connection,
                """
                select result, code, status
                  from place_activation(
                    @accountId, @accountSecurityStamp, @emailAddress, @code, now(), 4::smallint, 0::smallint,
                    now() + interval '1 month', 1::smallint, 1::smallint, 'backend'::text, 3::smallint, null::interval);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("emailAddress", "reader@example.com"),
                ("code", "good-code"));

            placed.ShouldBeTrue();
            placedCode.ShouldBe("ACTIVATION_STORED");
            placedStatus.ShouldBe((short)3);

            (bool stale, string staleCode, short? staleStatus) = await QueryActivationCommandAsync(
                connection,
                """
                select result, code, status
                  from place_activation(
                    @accountId, @accountSecurityStamp, @emailAddress, @code, now(), 4::smallint, 0::smallint,
                    now() + interval '1 month', 1::smallint, 1::smallint, 'backend'::text, 3::smallint, null::interval);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", Guid.NewGuid()),
                ("emailAddress", "reader@example.com"),
                ("code", "stale-code"));

            stale.ShouldBeFalse();
            staleCode.ShouldBe("ACCOUNT_SECURITY_STAMP_MISMATCH");
            staleStatus.ShouldBeNull();

            (bool invalidTerm, string invalidTermCode, short? invalidTermStatus) = await QueryActivationCommandAsync(
                connection,
                """
                select result, code, status
                  from place_activation(
                    @accountId, @accountSecurityStamp, @emailAddress, @code, now(), 99::smallint, 0::smallint,
                    now() + interval '1 month', 1::smallint, 1::smallint, 'backend'::text, 3::smallint, null::interval);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("emailAddress", "reader@example.com"),
                ("code", "invalid-term-code"));

            invalidTerm.ShouldBeFalse();
            invalidTermCode.ShouldBe("ACTIVATION_INVALID_TERM");
            invalidTermStatus.ShouldBeNull();

            (bool invalidRecycle, string invalidRecycleCode, short? invalidRecycleStatus) = await QueryActivationCommandAsync(
                connection,
                """
                select result, code, status
                  from place_activation(
                    @accountId, @accountSecurityStamp, @emailAddress, @code, now(), 4::smallint, 99::smallint,
                    now() + interval '1 month', 1::smallint, 1::smallint, 'backend'::text, 3::smallint, null::interval);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("emailAddress", "reader@example.com"),
                ("code", "invalid-recycle-code"));

            invalidRecycle.ShouldBeFalse();
            invalidRecycleCode.ShouldBe("ACTIVATION_INVALID_RECYCLE");
            invalidRecycleStatus.ShouldBeNull();

            (bool wrongCode, string wrongCodeResult, short? wrongFeatureSet, DateTimeOffset? wrongExpiration) = await QueryActivationVerifyAsync(
                connection,
                """
                select result, code, feature_set, off_at, day_duration, duration_repeat
                  from verify_activation(@accountId, @accountSecurityStamp, @emailAddress, @code, now(), 0::smallint, 1::smallint);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("emailAddress", "reader@example.com"),
                ("code", "not-the-code"));

            wrongCode.ShouldBeFalse();
            wrongCodeResult.ShouldBe("ACTIVATION_CODE_MISMATCH");
            wrongFeatureSet.ShouldBeNull();
            wrongExpiration.ShouldBeNull();

            await ExecuteAsync(
                connection,
                """
                insert into activations(
                    account_id, created_on, term, off_at, feature_set, code, status,
                    day_duration, duration_repeat, platform_backer, platform_text)
                values (
                    @accountId, now() - interval '2 months', interval '1 month', now() - interval '1 month',
                    1, 'expired-code', 3, 4, 0, 1, 'backend');
                """,
                ("accountId", accountId));

            (bool expired, string expiredCode, short? expiredFeatureSet, DateTimeOffset? expiredExpiration) = await QueryActivationVerifyAsync(
                connection,
                """
                select result, code, feature_set, off_at, day_duration, duration_repeat
                  from verify_activation(@accountId, @accountSecurityStamp, @emailAddress, @code, now(), 0::smallint, 1::smallint);
                """,
                ("accountId", accountId),
                ("accountSecurityStamp", accountSecurityStamp),
                ("emailAddress", "reader@example.com"),
                ("code", "expired-code"));

            expired.ShouldBeFalse();
            expiredCode.ShouldBe("ACTIVATION_EXPIRED");
            expiredFeatureSet.ShouldBeNull();
            expiredExpiration.ShouldBeNull();
        }
        finally
        {
            await ExecuteAsync(connection, $"drop schema if exists {schema} cascade;");
        }
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<Guid> QueryGuidAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (Guid)result;
    }

    private static async Task<(bool Result, string Code, short? Status)> QueryActivationCommandAsync(
        NpgsqlConnection connection,
        string sql,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return (
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetInt16(2));
    }

    private static async Task<(bool Result, string Code, short? FeatureSet, DateTimeOffset? Expiration)> QueryActivationVerifyAsync(
        NpgsqlConnection connection,
        string sql,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return (
            reader.GetBoolean(0),
            reader.GetString(1),
            reader.IsDBNull(2) ? null : reader.GetInt16(2),
            reader.IsDBNull(3) ? null : reader.GetFieldValue<DateTimeOffset>(3));
    }

    private static void AddParameters(NpgsqlCommand command, params (string Name, object? Value)[] parameters)
    {
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
    }

    private static string BaselinePath()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.csproj")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull();
        return Path.Combine(directory.FullName, "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql");
    }
}
