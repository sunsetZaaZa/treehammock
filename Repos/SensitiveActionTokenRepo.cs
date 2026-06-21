using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.DataLayer.Security;
using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;

public interface ISensitiveActionTokenRepo
{
    Task<AccountReauthenticationCredentialResult?> GetReauthenticationCredentials(
        Guid accountId,
        Guid accountSecurityStamp);

    Task<SensitiveActionTokenIssueCommandResult?> IssueToken(
        Guid accountId,
        Guid accountSecurityStamp,
        string sessionBindingHash,
        string tokenHash,
        SensitiveActionPurpose purpose,
        Instant createdOn,
        Instant expiration,
        bool consumeExistingTokens);

    Task<SensitiveActionTokenValidationCommandResult?> ValidateToken(
        Guid accountId,
        Guid accountSecurityStamp,
        string sessionBindingHash,
        string tokenHash,
        SensitiveActionPurpose purpose,
        bool consume,
        Instant moment);
}

public sealed class SensitiveActionTokenRepo : ISensitiveActionTokenRepo
{
    internal const string GetReauthenticationCredentialsFunction = "get_account_reauthentication_credentials";
    internal const string IssueSensitiveActionTokenFunction = "issue_sensitive_action_token";
    internal const string ValidateSensitiveActionTokenFunction = "validate_sensitive_action_token";

    private static readonly NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<SensitiveActionTokenRepo> _logger;

    public SensitiveActionTokenRepo(StorageContext activeDatabase, ILogger<SensitiveActionTokenRepo> logger)
    {
        _activeDatabase = activeDatabase;
        _logger = logger;
    }

    public async Task<AccountReauthenticationCredentialResult?> GetReauthenticationCredentials(
        Guid accountId,
        Guid accountSecurityStamp)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                GetReauthenticationCredentialsFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountReauthenticationCredentialResult result = await ReadAccountReauthenticationCredentialResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId });
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetReauthenticationCredentials), new { accountId });
            return null;
        }
    }

    public async Task<SensitiveActionTokenIssueCommandResult?> IssueToken(
        Guid accountId,
        Guid accountSecurityStamp,
        string sessionBindingHash,
        string tokenHash,
        SensitiveActionPurpose purpose,
        Instant createdOn,
        Instant expiration,
        bool consumeExistingTokens)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                IssueSensitiveActionTokenFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "sessionBindingHash",
                "tokenHash",
                "purpose",
                "createdOn",
                "expiration",
                "consumeExistingTokens");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@sessionBindingHash", NpgsqlDbType.Text).Value = sessionBindingHash;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@purpose", NpgsqlDbType.Smallint).Value = (short)purpose;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;
            command.Parameters.Add("@consumeExistingTokens", NpgsqlDbType.Boolean).Value = consumeExistingTokens;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                SensitiveActionTokenIssueCommandResult result = await ReadSensitiveActionTokenIssueCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, purpose });
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(IssueToken), new { accountId, purpose });
            return null;
        }
    }

    public async Task<SensitiveActionTokenValidationCommandResult?> ValidateToken(
        Guid accountId,
        Guid accountSecurityStamp,
        string sessionBindingHash,
        string tokenHash,
        SensitiveActionPurpose purpose,
        bool consume,
        Instant moment)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                ValidateSensitiveActionTokenFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "sessionBindingHash",
                "tokenHash",
                "purpose",
                "consume",
                "moment");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@sessionBindingHash", NpgsqlDbType.Text).Value = sessionBindingHash;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@purpose", NpgsqlDbType.Smallint).Value = (short)purpose;
            command.Parameters.Add("@consume", NpgsqlDbType.Boolean).Value = consume;
            command.Parameters.Add("@moment", InstantDbType).Value = moment;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                SensitiveActionTokenValidationCommandResult result = await ReadSensitiveActionTokenValidationCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, purpose });
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(ValidateToken), new { accountId, purpose });
            return null;
        }
    }

    internal static async Task<AccountReauthenticationCredentialResult> ReadAccountReauthenticationCredentialResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountReauthenticationCredentialResult(false, "NO_RESULT", null, null, null, null);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        byte[]? hashedPassword = dr.FieldCount > 2 && !dr.IsDBNull(2)
            ? ReadBytes(dr, 2)
            : null;
        VerificationStatus? verificationStatus = dr.FieldCount > 3 && !dr.IsDBNull(3)
            ? (VerificationStatus)dr.GetInt16(3)
            : null;
        Instant? cutOff = dr.FieldCount > 4 && !dr.IsDBNull(4)
            ? dr.GetFieldValue<Instant>(4)
            : null;
        Guid? accountSecurityStamp = dr.FieldCount > 5 && !dr.IsDBNull(5)
            ? dr.GetGuid(5)
            : null;

        return new AccountReauthenticationCredentialResult(
            result,
            code,
            hashedPassword,
            verificationStatus,
            cutOff,
            accountSecurityStamp);
    }

    internal static async Task<SensitiveActionTokenIssueCommandResult> ReadSensitiveActionTokenIssueCommandResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new SensitiveActionTokenIssueCommandResult(false, "NO_RESULT", null, null);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Guid? tokenId = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetGuid(2) : null;
        Instant? expiration = dr.FieldCount > 3 && !dr.IsDBNull(3) ? dr.GetFieldValue<Instant>(3) : null;

        return new SensitiveActionTokenIssueCommandResult(result, code, tokenId, expiration);
    }

    internal static async Task<SensitiveActionTokenValidationCommandResult> ReadSensitiveActionTokenValidationCommandResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new SensitiveActionTokenValidationCommandResult(false, "NO_RESULT", null);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Instant? expiration = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetFieldValue<Instant>(2) : null;

        return new SensitiveActionTokenValidationCommandResult(result, code, expiration);
    }

    private static byte[] ReadBytes(NpgsqlDataReader reader, int ordinal)
    {
        long length = reader.GetBytes(ordinal, 0, null, 0, 0);
        if (length <= 0 || length > int.MaxValue)
        {
            return Array.Empty<byte>();
        }

        byte[] buffer = new byte[length];
        reader.GetBytes(ordinal, 0, buffer, 0, buffer.Length);
        return buffer;
    }

    private async Task RollbackAndLogAsync(NpgsqlTransaction transaction, Exception exception, string commandText, object? scope = null)
    {
        try
        {
            await transaction.RollbackAsync();
        }
        catch (Exception rollbackException)
        {
            _logger.LogWarning(rollbackException, "Failed to roll back sensitive-action token repository transaction.");
        }

        LogRepositoryFailure(exception, commandText, scope);
    }

    private void LogRepositoryFailure(Exception exception, string operation, object? scope = null)
    {
        using IDisposable? _ = scope is null ? null : _logger.BeginScope(scope);
        _logger.LogError(exception, "Sensitive-action token repository operation failed: {Operation}", operation);
    }
}
