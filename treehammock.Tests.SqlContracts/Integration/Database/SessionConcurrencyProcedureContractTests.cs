using Npgsql;
using Shouldly;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class SessionConcurrencyProcedureContractTests
{
    [Fact]
    public async Task Set_session_serializes_concurrent_session_creation_for_the_same_account()
    {
        if (!DeferredSqlProcedureContractSettings.ShouldRun())
        {
            throw new InvalidOperationException(DeferredSqlProcedureContractSettings.SkipReason);
        }

        string connectionString = DeferredSqlProcedureContractSettings.ConnectionString!;
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "session_concurrency_" + Guid.NewGuid().ToString("N");

        try
        {
            await ExecuteAsync(setupConnection, $"create schema {schema};");
            await ExecuteAsync(setupConnection, $"set search_path to {schema};");
            await ExecuteAsync(setupConnection, File.ReadAllText(BaselinePath()));

            Guid accountId = Guid.NewGuid();
            byte[] hashedPassword = Enumerable.Repeat((byte)1, 128).ToArray();
            byte[] saltOne = Enumerable.Repeat((byte)2, 64).ToArray();
            byte[] siv = Enumerable.Repeat((byte)3, 32).ToArray();
            byte[] nonce = Enumerable.Repeat((byte)4, 16).ToArray();
            byte[] firstRefreshToken = Enumerable.Repeat((byte)5, 64).ToArray();
            byte[] secondRefreshToken = Enumerable.Repeat((byte)6, 64).ToArray();
            Guid firstSecurityStamp = Guid.Parse("11111111-1111-1111-1111-111111111111");
            Guid secondSecurityStamp = Guid.Parse("22222222-2222-2222-2222-222222222222");

            await ExecuteAsync(
                setupConnection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'concurrent-session@example.com', 'concurrent-session-reader', @hashedPassword, 'concurrent-session-web-key', @saltOne, @siv, @nonce,
                    0, 1, 0, 0);
                """,
                ("accountId", accountId),
                ("hashedPassword", hashedPassword),
                ("saltOne", saltOne),
                ("siv", siv),
                ("nonce", nonce));

            Guid accountSecurityStamp = await QueryGuidAsync(
                setupConnection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            await using var firstConnection = new NpgsqlConnection(connectionString);
            await firstConnection.OpenAsync();
            await ExecuteAsync(firstConnection, $"set search_path to {schema};");
            await using NpgsqlTransaction firstTransaction = await firstConnection.BeginTransactionAsync();

            (short firstResult, string firstCode) = await QueryShortStatusAsync(
                firstConnection,
                firstTransaction,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "concurrent-session-first"),
                ("accountId", accountId),
                ("refreshToken", firstRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(10)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", firstSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));

            firstResult.ShouldBe((short)1);
            firstCode.ShouldBe("SUCCESSFUL");

            await using var secondConnection = new NpgsqlConnection(connectionString);
            await secondConnection.OpenAsync();
            await ExecuteAsync(secondConnection, $"set search_path to {schema};");
            await using NpgsqlTransaction secondTransaction = await secondConnection.BeginTransactionAsync();

            Task<(short Result, string Code)> secondSetSessionTask = QueryShortStatusAsync(
                secondConnection,
                secondTransaction,
                """
                select result, code from set_session(
                    @accessTokenHash, @accountId, @refreshToken, @refreshes, @limit,
                    @createdOn, @sessionLifespan, @accessExpiration, @sessionExpiration, @cutOff, @features, @securityStamp, @accountSecurityStamp);
                """,
                ("accessTokenHash", "concurrent-session-second"),
                ("accountId", accountId),
                ("refreshToken", secondRefreshToken),
                ("refreshes", (short)0),
                ("limit", (short)5),
                ("createdOn", DateTimeOffset.UtcNow.AddMinutes(1)),
                ("sessionLifespan", TimeSpan.FromDays(7)),
                ("accessExpiration", DateTimeOffset.UtcNow.AddMinutes(20)),
                ("sessionExpiration", DateTimeOffset.UtcNow.AddDays(7)),
                ("cutOff", DateTimeOffset.UtcNow.AddDays(7)),
                ("features", (short)0),
                ("securityStamp", secondSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));

            Task completedBeforeCommit = await Task.WhenAny(secondSetSessionTask, Task.Delay(TimeSpan.FromSeconds(1)));
            completedBeforeCommit.ShouldNotBe(secondSetSessionTask, "A second direct login for the same account must wait on the first transaction's account-row lock.");

            await firstTransaction.CommitAsync();

            (short secondResult, string secondCode) = await secondSetSessionTask.WaitAsync(TimeSpan.FromSeconds(5));
            secondResult.ShouldBe((short)1);
            secondCode.ShouldBe("SUCCESSFUL");
            await secondTransaction.CommitAsync();

            long activeSessionCount = await QueryLongAsync(
                setupConnection,
                "select count(*) from sessions where account_id = @accountId and session_expiration > now();",
                ("accountId", accountId));
            activeSessionCount.ShouldBe(1);

            string currentActiveSession = await QueryStringAsync(
                setupConnection,
                "select active_access_token_hash from get_current_active_session_hash(@accountId);",
                ("accountId", accountId));
            currentActiveSession.ShouldBe("concurrent-session-second");

            (short staleTrustStatus, string staleTrustCode) = await QueryShortStatusAsync(
                setupConnection,
                null,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "concurrent-session-first"),
                ("accountId", accountId),
                ("securityStamp", firstSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            staleTrustStatus.ShouldBe((short)5);
            staleTrustCode.ShouldBe("SESSION_EXPIRED");

            (short currentTrustStatus, string currentTrustCode) = await QueryShortStatusAsync(
                setupConnection,
                null,
                "select status, code from validate_cached_session_trust(@accessTokenHash, @accountId, @securityStamp, @accountSecurityStamp);",
                ("accessTokenHash", "concurrent-session-second"),
                ("accountId", accountId),
                ("securityStamp", secondSecurityStamp),
                ("accountSecurityStamp", accountSecurityStamp));
            currentTrustStatus.ShouldBe((short)1);
            currentTrustCode.ShouldBe("VALID");
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<Guid> QueryGuidAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (Guid)result;
    }

    private static async Task<long> QueryLongAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (long)result;
    }

    private static async Task<string> QueryStringAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (string)result;
    }

    private static async Task<(short Result, string Code)> QueryShortStatusAsync(
        NpgsqlConnection connection,
        NpgsqlTransaction? transaction,
        string sql,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        if (transaction is not null)
        {
            command.Transaction = transaction;
        }

        AddParameters(command, parameters);

        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync();
        (await reader.ReadAsync()).ShouldBeTrue();

        return (reader.GetInt16(0), reader.GetString(1));
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
