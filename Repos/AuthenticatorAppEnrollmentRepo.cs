using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;

public sealed record AuthenticatorAppSetupBeginCommandResult(
    bool Result,
    string Code,
    short? TwoFactorIndex,
    Instant? Expiration);

public sealed record PendingAuthenticatorAppSetupRecord(
    bool Result,
    string Code,
    short? TwoFactorIndex,
    Instant? Expiration,
    short Attempts,
    byte[]? TotpSecretCiphertext,
    byte[]? TotpSecretNonce,
    byte[]? TotpSecretTag,
    int? TotpSecretVersion,
    long? TotpLastUsedStep,
    short? TotpProviderType);

public sealed record AuthenticatorAppSetupFailureCommandResult(
    bool Result,
    string Code,
    short Attempts,
    Instant? Expiration);

public sealed record AuthenticatorAppSetupCompletionCommandResult(
    bool Result,
    string Code,
    Guid? AccountSecurityStamp,
    short? TwoFactorIndex);

public sealed record AuthenticatorAppSetupCancelCommandResult(bool Result, string Code);

public sealed record VerifiedTotpEnrollmentRecord(
    Guid AccountId,
    short TwoFactorIndex,
    short Method,
    short TotpProviderType,
    string? TotpProviderEnrollmentId,
    string? TotpProviderAccountBindingHash,
    byte[]? TotpSecretCiphertext,
    byte[]? TotpSecretNonce,
    byte[]? TotpSecretTag,
    int? TotpSecretVersion,
    long? TotpLastUsedStep);

public sealed record TotpStepReplayCommandResult(bool Result, string Code);

public sealed record BeginAuthenticatorAppSetupCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SetupTokenHash,
    Instant CreatedOn,
    Instant Expiration,
    string AuthId,
    bool Required,
    TotpProviderType TotpProviderType,
    byte[]? TotpSecretCiphertext,
    byte[]? TotpSecretNonce,
    byte[]? TotpSecretTag,
    int? TotpSecretVersion);

public sealed record GetPendingAuthenticatorAppSetupCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SetupTokenHash,
    Instant Now);

public sealed record RecordAuthenticatorAppSetupFailureCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SetupTokenHash,
    short MaxAttempts,
    Instant Now);

public sealed record CompleteAuthenticatorAppSetupAndRotateSessionCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SetupTokenHash,
    long TimeStep,
    string ExpectedOldAccessTokenHash,
    string NewAccessTokenHash,
    byte[] RefreshToken,
    short Refreshes,
    short RefreshLimit,
    Instant CreatedOn,
    Duration SessionLifespan,
    Instant AccessExpiration,
    Instant SessionExpiration,
    Instant? CutOff,
    FeatureSet Features,
    Guid SessionSecurityStamp);

public sealed record CancelAuthenticatorAppSetupCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SetupTokenHash);

public interface IAuthenticatorAppEnrollmentRepo
{
    Task<AuthenticatorAppSetupBeginCommandResult?> BeginAuthenticatorAppSetupAsync(
        BeginAuthenticatorAppSetupCommand command,
        CancellationToken cancellationToken = default);

    Task<PendingAuthenticatorAppSetupRecord?> GetPendingAuthenticatorAppSetupAsync(
        GetPendingAuthenticatorAppSetupCommand command,
        CancellationToken cancellationToken = default);

    Task<AuthenticatorAppSetupFailureCommandResult?> RecordAuthenticatorAppSetupFailureAsync(
        RecordAuthenticatorAppSetupFailureCommand command,
        CancellationToken cancellationToken = default);

    Task<AuthenticatorAppSetupCompletionCommandResult?> CompleteAuthenticatorAppSetupAndRotateSessionAsync(
        CompleteAuthenticatorAppSetupAndRotateSessionCommand command,
        CancellationToken cancellationToken = default);

    Task<AuthenticatorAppSetupCancelCommandResult?> CancelAuthenticatorAppSetupAsync(
        CancelAuthenticatorAppSetupCommand command,
        CancellationToken cancellationToken = default);

    Task<VerifiedTotpEnrollmentRecord?> GetVerifiedTotpEnrollmentForAccountAsync(
        Guid accountId,
        Instant now,
        CancellationToken cancellationToken = default);

    Task<TotpStepReplayCommandResult?> MarkTotpStepUsedAsync(
        Guid accountId,
        short twoFactorIndex,
        long timeStep,
        CancellationToken cancellationToken = default);
}

public sealed class AuthenticatorAppEnrollmentRepo : IAuthenticatorAppEnrollmentRepo
{
    internal const string BeginAuthenticatorAppSetupFunction = "begin_authenticator_app_setup";
    internal const string GetPendingAuthenticatorAppSetupFunction = "get_pending_authenticator_app_setup";
    internal const string RecordAuthenticatorAppSetupFailureFunction = "record_authenticator_app_setup_failure";
    internal const string CompleteAuthenticatorAppSetupAndRotateSessionFunction = "complete_authenticator_app_setup_and_rotate_session";
    internal const string CancelAuthenticatorAppSetupFunction = "cancel_authenticator_app_setup";
    internal const string GetVerifiedTotpEnrollmentForAccountFunction = "get_verified_totp_enrollment_for_account";
    internal const string MarkTotpStepUsedFunction = "mark_totp_step_used";

    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;
    internal const NpgsqlDbType ProtectedSecretDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType AccessTokenHashDbType = NpgsqlDbType.Text;
    internal const NpgsqlDbType RefreshTokenDbType = NpgsqlDbType.Bytea;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<AuthenticatorAppEnrollmentRepo> _logger;

    public AuthenticatorAppEnrollmentRepo(
        StorageContext activeDatabase,
        ILogger<AuthenticatorAppEnrollmentRepo> logger)
    {
        _activeDatabase = activeDatabase;
        _logger = logger;
    }

    public async Task<AuthenticatorAppSetupBeginCommandResult?> BeginAuthenticatorAppSetupAsync(
        BeginAuthenticatorAppSetupCommand commandModel,
        CancellationToken cancellationToken = default)
    {
        const string procedure = BeginAuthenticatorAppSetupFunction;

        try
        {
            AccountSecurityStampGuard.Require(commandModel.AccountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "setupTokenHash",
                "createdOn",
                "expiration",
                "authId",
                "required",
                "totpProviderType",
                "totpSecretCiphertext",
                "totpSecretNonce",
                "totpSecretTag",
                "totpSecretVersion");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = commandModel.AccountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = commandModel.AccountSecurityStamp;
            command.Parameters.Add("@setupTokenHash", NpgsqlDbType.Text).Value = commandModel.SetupTokenHash;
            command.Parameters.Add("@createdOn", InstantDbType).Value = commandModel.CreatedOn;
            command.Parameters.Add("@expiration", InstantDbType).Value = commandModel.Expiration;
            command.Parameters.Add("@authId", NpgsqlDbType.Text).Value = commandModel.AuthId;
            command.Parameters.Add("@required", NpgsqlDbType.Boolean).Value = commandModel.Required;
            command.Parameters.Add("@totpProviderType", NpgsqlDbType.Smallint).Value = (short)commandModel.TotpProviderType;
            command.Parameters.Add("@totpSecretCiphertext", ProtectedSecretDbType).Value = DbValue(commandModel.TotpSecretCiphertext);
            command.Parameters.Add("@totpSecretNonce", ProtectedSecretDbType).Value = DbValue(commandModel.TotpSecretNonce);
            command.Parameters.Add("@totpSecretTag", ProtectedSecretDbType).Value = DbValue(commandModel.TotpSecretTag);
            command.Parameters.Add("@totpSecretVersion", NpgsqlDbType.Integer).Value = DbValue(commandModel.TotpSecretVersion);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                AuthenticatorAppSetupBeginCommandResult result = await ReadBeginResultAsync(dr, cancellationToken);
                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { commandModel.AccountId, commandModel.TotpProviderType });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(BeginAuthenticatorAppSetupAsync), new { commandModel.AccountId, commandModel.TotpProviderType });
            return null;
        }
    }

    public async Task<PendingAuthenticatorAppSetupRecord?> GetPendingAuthenticatorAppSetupAsync(
        GetPendingAuthenticatorAppSetupCommand commandModel,
        CancellationToken cancellationToken = default)
    {
        const string procedure = GetPendingAuthenticatorAppSetupFunction;

        try
        {
            AccountSecurityStampGuard.Require(commandModel.AccountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "setupTokenHash",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = commandModel.AccountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = commandModel.AccountSecurityStamp;
            command.Parameters.Add("@setupTokenHash", NpgsqlDbType.Text).Value = commandModel.SetupTokenHash;
            command.Parameters.Add("@now", InstantDbType).Value = commandModel.Now;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                PendingAuthenticatorAppSetupRecord result = await ReadPendingSetupAsync(dr, cancellationToken);
                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { commandModel.AccountId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetPendingAuthenticatorAppSetupAsync), new { commandModel.AccountId });
            return null;
        }
    }

    public async Task<AuthenticatorAppSetupFailureCommandResult?> RecordAuthenticatorAppSetupFailureAsync(
        RecordAuthenticatorAppSetupFailureCommand commandModel,
        CancellationToken cancellationToken = default)
    {
        const string procedure = RecordAuthenticatorAppSetupFailureFunction;

        try
        {
            AccountSecurityStampGuard.Require(commandModel.AccountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "setupTokenHash",
                "maxAttempts",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = commandModel.AccountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = commandModel.AccountSecurityStamp;
            command.Parameters.Add("@setupTokenHash", NpgsqlDbType.Text).Value = commandModel.SetupTokenHash;
            command.Parameters.Add("@maxAttempts", NpgsqlDbType.Smallint).Value = commandModel.MaxAttempts;
            command.Parameters.Add("@now", InstantDbType).Value = commandModel.Now;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                AuthenticatorAppSetupFailureCommandResult result = await ReadFailureResultAsync(dr, cancellationToken);
                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { commandModel.AccountId, commandModel.MaxAttempts });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RecordAuthenticatorAppSetupFailureAsync), new { commandModel.AccountId, commandModel.MaxAttempts });
            return null;
        }
    }

    public async Task<AuthenticatorAppSetupCompletionCommandResult?> CompleteAuthenticatorAppSetupAndRotateSessionAsync(
        CompleteAuthenticatorAppSetupAndRotateSessionCommand commandModel,
        CancellationToken cancellationToken = default)
    {
        const string procedure = CompleteAuthenticatorAppSetupAndRotateSessionFunction;

        try
        {
            AccountSecurityStampGuard.Require(commandModel.AccountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "setupTokenHash",
                "timeStep",
                "expectedOldAccessTokenHash",
                "newAccessTokenHash",
                "refreshToken",
                "refreshes",
                "refreshLimit",
                "createdOn",
                "sessionLifespan",
                "accessExpiration",
                "sessionExpiration",
                "cutOff",
                "features",
                "sessionSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = commandModel.AccountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = commandModel.AccountSecurityStamp;
            command.Parameters.Add("@setupTokenHash", NpgsqlDbType.Text).Value = commandModel.SetupTokenHash;
            command.Parameters.Add("@timeStep", NpgsqlDbType.Bigint).Value = commandModel.TimeStep;
            command.Parameters.Add("@expectedOldAccessTokenHash", AccessTokenHashDbType).Value = commandModel.ExpectedOldAccessTokenHash;
            command.Parameters.Add("@newAccessTokenHash", AccessTokenHashDbType).Value = commandModel.NewAccessTokenHash;
            command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = commandModel.RefreshToken;
            command.Parameters.Add("@refreshes", NpgsqlDbType.Smallint).Value = commandModel.Refreshes;
            command.Parameters.Add("@refreshLimit", NpgsqlDbType.Smallint).Value = commandModel.RefreshLimit;
            command.Parameters.Add("@createdOn", InstantDbType).Value = commandModel.CreatedOn;
            command.Parameters.Add("@sessionLifespan", NpgsqlDbType.Interval).Value = commandModel.SessionLifespan;
            command.Parameters.Add("@accessExpiration", InstantDbType).Value = commandModel.AccessExpiration;
            command.Parameters.Add("@sessionExpiration", InstantDbType).Value = commandModel.SessionExpiration;
            command.Parameters.Add("@cutOff", InstantDbType).Value = DbValue(commandModel.CutOff);
            command.Parameters.Add("@features", NpgsqlDbType.Smallint).Value = (short)commandModel.Features;
            command.Parameters.Add("@sessionSecurityStamp", NpgsqlDbType.Uuid).Value = commandModel.SessionSecurityStamp;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                AuthenticatorAppSetupCompletionCommandResult result = await ReadCompletionResultAsync(dr, cancellationToken);
                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { commandModel.AccountId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CompleteAuthenticatorAppSetupAndRotateSessionAsync), new { commandModel.AccountId });
            return null;
        }
    }

    public async Task<AuthenticatorAppSetupCancelCommandResult?> CancelAuthenticatorAppSetupAsync(
        CancelAuthenticatorAppSetupCommand commandModel,
        CancellationToken cancellationToken = default)
    {
        const string procedure = CancelAuthenticatorAppSetupFunction;

        try
        {
            AccountSecurityStampGuard.Require(commandModel.AccountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "setupTokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = commandModel.AccountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = commandModel.AccountSecurityStamp;
            command.Parameters.Add("@setupTokenHash", NpgsqlDbType.Text).Value = commandModel.SetupTokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                AuthenticatorAppSetupCancelCommandResult result = await ReadCancelResultAsync(dr, cancellationToken);
                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { commandModel.AccountId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CancelAuthenticatorAppSetupAsync), new { commandModel.AccountId });
            return null;
        }
    }

    public async Task<VerifiedTotpEnrollmentRecord?> GetVerifiedTotpEnrollmentForAccountAsync(
        Guid accountId,
        Instant now,
        CancellationToken cancellationToken = default)
    {
        const string procedure = GetVerifiedTotpEnrollmentForAccountFunction;

        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@now", InstantDbType).Value = now;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                VerifiedTotpEnrollmentRecord? result = await ReadVerifiedEnrollmentAsync(dr, cancellationToken);
                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetVerifiedTotpEnrollmentForAccountAsync), new { accountId });
            return null;
        }
    }

    public async Task<TotpStepReplayCommandResult?> MarkTotpStepUsedAsync(
        Guid accountId,
        short twoFactorIndex,
        long timeStep,
        CancellationToken cancellationToken = default)
    {
        const string procedure = MarkTotpStepUsedFunction;

        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync(cancellationToken);
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "twoFactorIndex",
                "timeStep");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@twoFactorIndex", NpgsqlDbType.Smallint).Value = twoFactorIndex;
            command.Parameters.Add("@timeStep", NpgsqlDbType.Bigint).Value = timeStep;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync(cancellationToken);
                TotpStepReplayCommandResult result = await ReadReplayResultAsync(dr, cancellationToken);
                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId, twoFactorIndex, timeStep });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(MarkTotpStepUsedAsync), new { accountId, twoFactorIndex, timeStep });
            return null;
        }
    }

    internal static async Task<AuthenticatorAppSetupBeginCommandResult> ReadBeginResultAsync(
        NpgsqlDataReader reader,
        CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new AuthenticatorAppSetupBeginCommandResult(false, "NO_RESULT", null, null);
        }

        return new AuthenticatorAppSetupBeginCommandResult(
            ReadBool(reader, 0),
            ReadString(reader, 1),
            reader.IsDBNull(2) ? null : reader.GetInt16(2),
            reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3));
    }

    internal static async Task<PendingAuthenticatorAppSetupRecord> ReadPendingSetupAsync(
        NpgsqlDataReader reader,
        CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new PendingAuthenticatorAppSetupRecord(false, "NO_RESULT", null, null, 0, null, null, null, null, null, null);
        }

        return new PendingAuthenticatorAppSetupRecord(
            ReadBool(reader, 0),
            ReadString(reader, 1),
            reader.IsDBNull(2) ? null : reader.GetInt16(2),
            reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3),
            reader.IsDBNull(4) ? (short)0 : reader.GetInt16(4),
            reader.IsDBNull(5) ? null : ReadBytes(reader, 5),
            reader.IsDBNull(6) ? null : ReadBytes(reader, 6),
            reader.IsDBNull(7) ? null : ReadBytes(reader, 7),
            reader.IsDBNull(8) ? null : reader.GetInt32(8),
            reader.IsDBNull(9) ? null : reader.GetInt64(9),
            reader.IsDBNull(10) ? null : reader.GetInt16(10));
    }

    internal static async Task<AuthenticatorAppSetupFailureCommandResult> ReadFailureResultAsync(
        NpgsqlDataReader reader,
        CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new AuthenticatorAppSetupFailureCommandResult(false, "NO_RESULT", 0, null);
        }

        return new AuthenticatorAppSetupFailureCommandResult(
            ReadBool(reader, 0),
            ReadString(reader, 1),
            reader.IsDBNull(2) ? (short)0 : reader.GetInt16(2),
            reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3));
    }

    internal static async Task<AuthenticatorAppSetupCompletionCommandResult> ReadCompletionResultAsync(
        NpgsqlDataReader reader,
        CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new AuthenticatorAppSetupCompletionCommandResult(false, "NO_RESULT", null, null);
        }

        return new AuthenticatorAppSetupCompletionCommandResult(
            ReadBool(reader, 0),
            ReadString(reader, 1),
            reader.IsDBNull(2) ? null : reader.GetGuid(2),
            reader.IsDBNull(3) ? null : reader.GetInt16(3));
    }

    internal static async Task<AuthenticatorAppSetupCancelCommandResult> ReadCancelResultAsync(
        NpgsqlDataReader reader,
        CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new AuthenticatorAppSetupCancelCommandResult(false, "NO_RESULT");
        }

        return new AuthenticatorAppSetupCancelCommandResult(ReadBool(reader, 0), ReadString(reader, 1));
    }

    internal static async Task<VerifiedTotpEnrollmentRecord?> ReadVerifiedEnrollmentAsync(
        NpgsqlDataReader reader,
        CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new VerifiedTotpEnrollmentRecord(
            reader.GetGuid(0),
            reader.GetInt16(1),
            reader.GetInt16(2),
            reader.GetInt16(3),
            reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5),
            reader.IsDBNull(6) ? null : ReadBytes(reader, 6),
            reader.IsDBNull(7) ? null : ReadBytes(reader, 7),
            reader.IsDBNull(8) ? null : ReadBytes(reader, 8),
            reader.IsDBNull(9) ? null : reader.GetInt32(9),
            reader.IsDBNull(10) ? null : reader.GetInt64(10));
    }

    internal static async Task<TotpStepReplayCommandResult> ReadReplayResultAsync(
        NpgsqlDataReader reader,
        CancellationToken cancellationToken = default)
    {
        if (!await reader.ReadAsync(cancellationToken))
        {
            return new TotpStepReplayCommandResult(false, "NO_RESULT");
        }

        return new TotpStepReplayCommandResult(ReadBool(reader, 0), ReadString(reader, 1));
    }

    private static bool ReadBool(NpgsqlDataReader reader, int ordinal)
    {
        return !reader.IsDBNull(ordinal) && reader.GetBoolean(ordinal);
    }

    private static string ReadString(NpgsqlDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? "UNKNOWN" : reader.GetString(ordinal);
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

    private static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
    }

    private async Task RollbackAndLogAsync(NpgsqlTransaction transaction, Exception exception, string procedure, object? scope = null)
    {
        try
        {
            await transaction.RollbackAsync();
        }
        catch (Exception rollbackException)
        {
            _logger.LogWarning(rollbackException, "Failed to roll back authenticator-app enrollment repository transaction.");
        }

        LogRepositoryFailure(exception, procedure, scope);
    }

    private void LogRepositoryFailure(Exception exception, string operation, object? scope = null)
    {
        using IDisposable? _ = scope is null ? null : _logger.BeginScope(scope);
        _logger.LogError(exception, "Authenticator-app enrollment repository operation failed: {Operation}", operation);
    }
}
