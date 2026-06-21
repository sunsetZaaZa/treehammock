using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;

public sealed record AccountRecoveryLookupResult(
    bool Result,
    string Code,
    Guid? AccountId,
    string? EmailAddress,
    string? PhoneNumber,
    string? PhoneCountryCode,
    Guid? AccountSecurityStamp,
    Instant? UnlockWhen);

public interface IAccountRecoveryRepo
{
    Task<AccountRecoveryLookupResult?> LookupLockedAccount(string identifier, Instant now);
    Task<AccountRecovery_Status?> BeginUnlock(
        Guid accountId,
        string token,
        Instant createdOn,
        Instant expiration,
        AccountRecovery_Status status,
        AccountUnlockDeliveryMethod deliveryMethod,
        Guid accountSecurityStamp,
        Instant lockoutUnlockWhen);

    Task<AccountRecovery_Status?> CancelUnlock(Guid accountId, string token);
    Task<AccountRecovery_Status?> VerifyUnlock(string token);
}

public class AccountRecoveryRepo : IAccountRecoveryRepo
{
    internal const string LookupRecoveryAccountFunction = "lookup_locked_recovery_account";
    internal const string BeginRecoveryProcedure = "start_unlock_account";
    internal const string CancelRecoveryProcedure = "cancel_unlock_account";
    internal const string VerifyRecoveryProcedure = "verify_unlock_account";
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<AccountRecoveryRepo> _logger;

    public AccountRecoveryRepo(StorageContext database, ILogger<AccountRecoveryRepo> logger)
    {
        _activeDatabase = database;
        _logger = logger;
    }

    public async Task<AccountRecoveryLookupResult?> LookupLockedAccount(string identifier, Instant now)
    {
        try
        {
            const string procedure = LookupRecoveryAccountFunction;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "identifier",
                "now");

            command.Parameters.Add("@identifier", NpgsqlDbType.Text).Value = identifier;
            command.Parameters.Add("@now", InstantDbType).Value = now;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    var result = new AccountRecoveryLookupResult(
                        dr.GetBoolean(0),
                        dr.GetString(1),
                        dr.IsDBNull(2) ? null : dr.GetGuid(2),
                        dr.IsDBNull(3) ? null : dr.GetString(3),
                        dr.IsDBNull(4) ? null : dr.GetString(4),
                        dr.IsDBNull(5) ? null : dr.GetString(5),
                        dr.IsDBNull(6) ? null : dr.GetGuid(6),
                        dr.IsDBNull(7) ? null : dr.GetFieldValue<Instant>(7));

                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return result;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.IdentifierLookup(identifier, now));
            }

            return null;
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(LookupLockedAccount));
            return null;
        }
    }

    public async Task<AccountRecovery_Status?> BeginUnlock(
        Guid accountId,
        string token,
        Instant createdOn,
        Instant expiration,
        AccountRecovery_Status status,
        AccountUnlockDeliveryMethod deliveryMethod,
        Guid accountSecurityStamp,
        Instant lockoutUnlockWhen)
    {
        try
        {
            const string procedure = BeginRecoveryProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "tokenHash",
                "createdOn",
                "expiration",
                "status",
                "method",
                "accountSecurityStamp",
                "lockoutUnlockWhen");

            string tokenHash = SecretHashUtility.HashToken(token);

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;
            command.Parameters.Add("@status", NpgsqlDbType.Smallint).Value = (short)status;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)deliveryMethod;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@lockoutUnlockWhen", InstantDbType).Value = lockoutUnlockWhen;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    AccountRecovery_Status result = (AccountRecovery_Status)dr.GetInt16(0);
                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return result;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(
                    tran,
                    ex,
                    procedure,
                    new { accountId, createdOn, expiration, status, deliveryMethod, accountSecurityStamp, lockoutUnlockWhen });
            }

            return null;
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(BeginUnlock));
            return null;
        }
    }

    public async Task<AccountRecovery_Status?> CancelUnlock(Guid accountId, string token)
    {
        try
        {
            const string procedure = CancelRecoveryProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "tokenHash");

            string tokenHash = SecretHashUtility.HashToken(token);
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    AccountRecovery_Status result = (AccountRecovery_Status)dr.GetInt16(0);
                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return result;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId });
            }

            return null;
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CancelUnlock));
            return null;
        }
    }

    public async Task<AccountRecovery_Status?> VerifyUnlock(string token)
    {
        try
        {
            const string procedure = VerifyRecoveryProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "tokenHash");

            string tokenHash = SecretHashUtility.HashToken(token);
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    AccountRecovery_Status result = (AccountRecovery_Status)dr.GetInt16(0);
                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return result;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.VerificationTokenHashScope(tokenHash));
            }

            return null;
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(VerifyUnlock));
            return null;
        }
    }


    private void LogRepositoryFailure(Exception exception, string operation, object? scope = null)
    {
        _logger.LogError(exception, "Repository operation {Operation} failed before a controlled repository result could be returned with scope {@Scope}.", operation, scope);
    }

    private async Task RollbackAndLogAsync(NpgsqlTransaction tran, Exception exception, string procedure, object? scope = null)
    {
        try
        {
            await tran.RollbackAsync();
        }
        catch (Exception rollbackException)
        {
            _logger.LogError(rollbackException, "Rollback failed for repository procedure {Procedure}.", procedure);
        }

        _logger.LogError(exception, "Repository procedure {Procedure} failed with scope {@Scope}.", procedure, scope);
    }
}
