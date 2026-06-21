using Microsoft.Extensions.Logging;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.DataLayer;
using treehammock.Rigging.Database;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Repos;

public interface IActivationRepo
{
    Task<ActivationCommandResult?> PlaceActivation(
        Guid accountId,
        Guid accountSecurityStamp,
        string emailAddress,
        string code,
        Instant createdOn,
        DayDuration term,
        DurationRepeat interval,
        Instant closeOff,
        FeatureSet featureSet,
        PlatformBacker platformBacker,
        string platformText,
        ActivationStatus status,
        Period? delayedStart);

    Task<ActivationCommandResult?> CancelActivationRequest(Guid accountId, Guid accountSecurityStamp, string code, Instant cancelledOn);
    Task<ActivationCommandResult?> DisableActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, Instant createdOn, Instant closeOff, ActivationStatus status);
    Task<ActivationVerifyCommandResult?> VerifyActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, string code, Instant createdOn, ushort position, ushort upperLimit);
}

public class ActivationRepo : IActivationRepo
{
    internal const string PlaceActivationProcedure = "place_activation";
    internal const string CancelActivationRequestProcedure = "cancel_activation_request";
    internal const string DisableActivationProcedure = "disable_activation";
    internal const string VerifyActivationProcedure = "verify_activation";
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;

    private readonly StorageContext _activeDatabase;
    private readonly ILogger<ActivationRepo> _logger;

    public ActivationRepo(StorageContext database, ILogger<ActivationRepo> logger)
    {
        _activeDatabase = database;
        _logger = logger;
    }

    public async Task<ActivationCommandResult?> PlaceActivation(
        Guid accountId,
        Guid accountSecurityStamp,
        string emailAddress,
        string code,
        Instant createdOn,
        DayDuration term,
        DurationRepeat interval,
        Instant closeOff,
        FeatureSet featureSet,
        PlatformBacker platformBacker,
        string platformText,
        ActivationStatus status,
        Period? delayedStart)
    {
        try
        {
            const string procedure = PlaceActivationProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "emailAddress",
                "code",
                "createdOn",
                "term",
                "interval",
                "closeOff",
                "featureSet",
                "platformBacker",
                "platformText",
                "status",
                "delayedStart");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@code", NpgsqlDbType.Text).Value = code;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@term", NpgsqlDbType.Smallint).Value = (short)term;
            command.Parameters.Add("@interval", NpgsqlDbType.Smallint).Value = (short)interval;
            command.Parameters.Add("@closeOff", InstantDbType).Value = closeOff;
            command.Parameters.Add("@featureSet", NpgsqlDbType.Smallint).Value = (short)featureSet;
            command.Parameters.Add("@platformBacker", NpgsqlDbType.Smallint).Value = (short)platformBacker;
            command.Parameters.Add("@platformText", NpgsqlDbType.Text).Value = platformText;
            command.Parameters.Add("@status", NpgsqlDbType.Smallint).Value = (short)status;
            command.Parameters.Add("@delayedStart", NpgsqlDbType.Interval).Value = DbValue(delayedStart);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                ActivationCommandResult? result = await ReadActivationCommandResultAsync(dr);
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.ActivationEmail(accountId, emailAddress, createdOn, closeOff, status));
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(PlaceActivation));
            return null;
        }
    }

    public async Task<ActivationCommandResult?> CancelActivationRequest(Guid accountId, Guid accountSecurityStamp, string code, Instant cancelledOn)
    {
        try
        {
            const string procedure = CancelActivationRequestProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "code",
                "cancelledOn");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@code", NpgsqlDbType.Text).Value = code;
            command.Parameters.Add("@cancelledOn", InstantDbType).Value = cancelledOn;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                ActivationCommandResult? result = await ReadActivationCommandResultAsync(dr);
                await tran.CommitAsync();
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
            LogRepositoryFailure(ex, nameof(CancelActivationRequest));
            return null;
        }
    }

    public async Task<ActivationCommandResult?> DisableActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, Instant createdOn, Instant closeOff, ActivationStatus status)
    {
        try
        {
            const string procedure = DisableActivationProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "emailAddress",
                "createdOn",
                "closeOff",
                "status");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@closeOff", InstantDbType).Value = closeOff;
            command.Parameters.Add("@status", NpgsqlDbType.Smallint).Value = (short)status;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                ActivationCommandResult? result = await ReadActivationCommandResultAsync(dr);
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.ActivationEmail(accountId, emailAddress, createdOn, closeOff, status));
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(DisableActivation));
            return null;
        }
    }

    public async Task<ActivationVerifyCommandResult?> VerifyActivation(Guid accountId, Guid accountSecurityStamp, string emailAddress, string code, Instant createdOn, ushort position, ushort upperLimit)
    {
        try
        {
            const string procedure = VerifyActivationProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "emailAddress",
                "code",
                "createdOn",
                "position",
                "upperLimit");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@code", NpgsqlDbType.Text).Value = code;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@position", NpgsqlDbType.Smallint).Value = (short)position;
            command.Parameters.Add("@upperLimit", NpgsqlDbType.Smallint).Value = (short)upperLimit;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                ActivationVerifyCommandResult? result = await ReadActivationVerifyCommandResultAsync(dr);
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.ActivationVerificationEmail(accountId, emailAddress, position, upperLimit));
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(VerifyActivation));
            return null;
        }
    }

    internal static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
    }

    private static async Task<ActivationCommandResult?> ReadActivationCommandResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return null;
        }

        ActivationStatus? status = dr.IsDBNull(2) ? null : (ActivationStatus)dr.GetInt16(2);
        return new ActivationCommandResult(dr.GetBoolean(0), dr.GetString(1), status);
    }

    private static async Task<ActivationVerifyCommandResult?> ReadActivationVerifyCommandResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return null;
        }

        bool result = dr.GetBoolean(0);
        string code = dr.GetString(1);
        ActivationQuery? activation = null;

        if (result)
        {
            activation = new ActivationQuery(
                (FeatureSet)dr.GetInt16(2),
                dr.GetFieldValue<Instant>(3),
                (DayDuration)dr.GetInt16(4),
                (DurationRepeat)dr.GetInt16(5));
        }

        return new ActivationVerifyCommandResult(result, code, activation);
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
