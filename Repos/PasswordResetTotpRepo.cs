using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Rigging.Database;

namespace treehammock.Repos;

public sealed record PasswordResetTotpEnrollmentRecord(
    Guid AccountId,
    short TwoFactorIndex,
    short Method,
    byte[] TotpSecretCiphertext,
    byte[] TotpSecretNonce,
    byte[] TotpSecretTag,
    int TotpSecretVersion,
    long? TotpLastUsedStep);

public sealed record PasswordResetTotpStepResult(bool Result, string Code);

public interface IPasswordResetTotpRepo
{
    Task<PasswordResetTotpEnrollmentRecord?> GetPasswordResetTotpEnrollmentAsync(
        Guid accountId,
        Instant now,
        CancellationToken cancellationToken);

    Task<PasswordResetTotpStepResult?> MarkPasswordResetTotpStepUsedAsync(
        Guid accountId,
        short twoFactorIndex,
        long timeStep,
        CancellationToken cancellationToken);
}

public sealed class PasswordResetTotpRepo : IPasswordResetTotpRepo
{
    internal const string GetPasswordResetTotpEnrollmentFunction = "get_password_reset_totp_enrollment";
    internal const string MarkPasswordResetTotpStepUsedFunction = "mark_password_reset_totp_step_used";
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;
    internal const NpgsqlDbType ProtectedSecretDbType = NpgsqlDbType.Bytea;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<PasswordResetTotpRepo> _logger;

    public PasswordResetTotpRepo(StorageContext database, ILogger<PasswordResetTotpRepo> logger)
    {
        _activeDatabase = database;
        _logger = logger;
    }

    public async Task<PasswordResetTotpEnrollmentRecord?> GetPasswordResetTotpEnrollmentAsync(
        Guid accountId,
        Instant now,
        CancellationToken cancellationToken)
    {
        const string procedure = GetPasswordResetTotpEnrollmentFunction;

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
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetTotpEnrollmentRecord result = new(
                        dr.GetGuid(0),
                        dr.GetInt16(1),
                        dr.GetInt16(2),
                        dr.GetFieldValue<byte[]>(3),
                        dr.GetFieldValue<byte[]>(4),
                        dr.GetFieldValue<byte[]>(5),
                        dr.GetInt32(6),
                        dr.IsDBNull(7) ? null : dr.GetInt64(7));

                    await dr.DisposeAsync();
                    await tran.CommitAsync(cancellationToken);
                    return result;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return null;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetPasswordResetTotpEnrollmentAsync), new { accountId });
            return null;
        }
    }

    public async Task<PasswordResetTotpStepResult?> MarkPasswordResetTotpStepUsedAsync(
        Guid accountId,
        short twoFactorIndex,
        long timeStep,
        CancellationToken cancellationToken)
    {
        const string procedure = MarkPasswordResetTotpStepUsedFunction;

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
                if (await dr.ReadAsync(cancellationToken))
                {
                    PasswordResetTotpStepResult result = new(
                        dr.GetBoolean(0),
                        dr.GetString(1));

                    await dr.DisposeAsync();
                    await tran.CommitAsync(cancellationToken);
                    return result;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync(cancellationToken);
                return null;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId, twoFactorIndex, timeStep });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(MarkPasswordResetTotpStepUsedAsync), new { accountId, twoFactorIndex, timeStep });
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
