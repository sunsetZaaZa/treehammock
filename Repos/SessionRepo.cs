using System.Data;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using NpgsqlTypes;

using treehammock.Entities;
using treehammock.DataLayer.Account;
using treehammock.Rigging.Config;
using treehammock.Rigging.Authorization;
using treehammock.RiggingSupport.Enum;
using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Status;

namespace treehammock.Repos;

public interface ISessionRepo
{
    public Task<Session?> GetSession(string accessTokenHash);
    public Task<IntraMessage?> SetSession(string accessTokenHash, Session record);
    public Task<SessionRotationResult?> RotateActiveSession(Guid accountId, string expectedOldAccessTokenHash, string newAccessTokenHash, Session newSession);
    public Task<CachedSessionTrustResult?> ValidateCachedSessionTrust(string accessTokenHash, Guid accountId, Guid securityStamp, Guid accountSecurityStamp);
    public Task<bool?> ExpireSession(string accessTokenHash, Instant? newExpiration);
    public Task<bool?> UpdateRefreshToken(Guid accountId, byte[] refreshToken);
    public Task<DbCommandResult?> LogoutCurrentSession(Guid accountId, string accessTokenHash, Guid accountSecurityStamp);
    public Task<AccountStampRotationResult?> LogoutAllSessions(Guid accountId, Guid accountSecurityStamp);
    public Task<IReadOnlyList<AccountSessionSummary>?> ListActiveSessions(Guid accountId, Guid accountSecurityStamp, string currentAccessTokenHash);
    public Task<DbCommandResult?> RevokeSessionForAccount(Guid accountId, Guid targetSessionId, Guid accountSecurityStamp, string currentAccessTokenHash);
}

public class SessionRepo : ISessionRepo
{
    internal const string GetSessionProcedure = "get_session";
    internal const string SetSessionProcedure = "set_session";
    internal const string ExpireSessionProcedure = "expire_session";
    internal const string RotateActiveSessionProcedure = "rotate_active_session";
    internal const string ValidateCachedSessionTrustProcedure = "validate_cached_session_trust";
    internal const string UpdateRefreshTokenProcedure = "update_refresh_token";
    internal const string LogoutCurrentSessionProcedure = "logout_current_session";
    internal const string LogoutAllSessionsProcedure = "logout_all_sessions";
    internal const string ListActiveSessionsProcedure = "list_active_sessions";
    internal const string RevokeSessionForAccountProcedure = "revoke_session_for_account";

    internal const NpgsqlDbType AccessTokenHashDbType = NpgsqlDbType.Text;
    internal const NpgsqlDbType RefreshTokenDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;
    internal const NpgsqlDbType FeatureSetDbType = NpgsqlDbType.Smallint;
    internal const NpgsqlDbType SecurityStampDbType = NpgsqlDbType.Uuid;
    internal const NpgsqlDbType SessionIdDbType = NpgsqlDbType.Uuid;

    private readonly StorageContext _activeDatabase;
    private readonly JWTSettings _jwtSettings;
    private readonly ILogger<SessionRepo> _logger;

    public SessionRepo(StorageContext database, IOptions<JWTSettings> jwtSettings, ILogger<SessionRepo> logger)
    {
        _activeDatabase = database;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
    }

    public async Task<Session?> GetSession(string accessTokenHash)
    {
        try
        {
            const string procedure = GetSessionProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, "accessTokenHash");

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    byte[] refreshTokenBuffer = new byte[_jwtSettings.RefreshTokenBytes];
                    dr.GetBytes(1, 0, refreshTokenBuffer, 0, _jwtSettings.RefreshTokenBytes);

                    Period? sessionLifespan = dr.IsDBNull(5) ? null : dr.GetFieldValue<Period>(5);
                    Instant accessExpiration = dr.GetFieldValue<Instant>(6);
                    Instant sessionExpiration = dr.GetFieldValue<Instant>(7);
                    Instant? cutOff = dr.FieldCount > 8 && !dr.IsDBNull(8) ? dr.GetFieldValue<Instant>(8) : null;
                    FeatureSet features = dr.FieldCount > 9 && !dr.IsDBNull(9) ? (FeatureSet)dr.GetInt16(9) : FeatureSet.basic;
                    Guid securityStamp = dr.FieldCount > 10 && !dr.IsDBNull(10)
                        ? dr.GetGuid(10)
                        : throw new DataException("get_session must return security_stamp.");
                    Guid accountSecurityStamp = dr.FieldCount > 11 && !dr.IsDBNull(11)
                        ? dr.GetGuid(11)
                        : throw new DataException("get_session must return account_security_stamp.");

                    var session = new Session(
                        dr.GetGuid(0),
                        refreshTokenBuffer,
                        dr.IsDBNull(2) ? null : dr.GetInt16(2),
                        dr.IsDBNull(3) ? null : dr.GetInt16(3),
                        dr.GetFieldValue<Instant>(4),
                        sessionLifespan,
                        accessExpiration,
                        sessionExpiration,
                        cutOff,
                        features,
                        securityStamp,
                        accountSecurityStamp);

                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return session;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccessTokenHashScope(accessTokenHash));
            }

            return null;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetSession));
            return null;
        }
    }

    public async Task<IntraMessage?> SetSession(string accessTokenHash, Session workingSession)
    {
        try
        {
            const string procedure = SetSessionProcedure;
            string[] parameterNames =
            {
                "accessTokenHash",
                "accountId",
                "refreshToken",
                "refreshes",
                "limit",
                "createdOn",
                "sessionLifespan",
                "accessExpiration",
                "sessionExpiration",
                "cutOff",
                "features",
                "securityStamp",
                "accountSecurityStamp"
            };

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, parameterNames);

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = workingSession.accountId;
            command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = workingSession.refreshToken;
            command.Parameters.Add("@refreshes", NpgsqlDbType.Smallint).Value = DbValue(workingSession.refreshes);
            command.Parameters.Add("@limit", NpgsqlDbType.Smallint).Value = DbValue(workingSession.limit);
            command.Parameters.Add("@createdOn", InstantDbType).Value = workingSession.createdOn;
            command.Parameters.Add("@sessionLifespan", NpgsqlDbType.Interval).Value = DbValue(workingSession.sessionLifespan);
            command.Parameters.Add("@accessExpiration", InstantDbType).Value = workingSession.accessExpiration;
            command.Parameters.Add("@sessionExpiration", InstantDbType).Value = workingSession.sessionExpiration;
            command.Parameters.Add("@cutOff", InstantDbType).Value = DbValue(workingSession.cutOff);
            command.Parameters.Add("@features", FeatureSetDbType).Value = (short)workingSession.features;
            command.Parameters.Add("@securityStamp", SecurityStampDbType).Value = workingSession.securityStamp;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(workingSession.accountSecurityStamp);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    IntraMessage result = (IntraMessage)dr.GetInt16(dr.GetOrdinal("result"));
                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return result;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHash(workingSession.accountId, accessTokenHash));
            }

            return null;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(SetSession));
            return null;
        }
    }


    public async Task<SessionRotationResult?> RotateActiveSession(Guid accountId, string expectedOldAccessTokenHash, string newAccessTokenHash, Session newSession)
    {
        try
        {
            const string procedure = RotateActiveSessionProcedure;
            string[] parameterNames =
            {
                "accountId",
                "expectedOldAccessTokenHash",
                "newAccessTokenHash",
                "refreshToken",
                "refreshes",
                "limit",
                "createdOn",
                "sessionLifespan",
                "accessExpiration",
                "sessionExpiration",
                "cutOff",
                "features",
                "securityStamp",
                "accountSecurityStamp"
            };

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, parameterNames);

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@expectedOldAccessTokenHash", AccessTokenHashDbType).Value = expectedOldAccessTokenHash;
            command.Parameters.Add("@newAccessTokenHash", AccessTokenHashDbType).Value = newAccessTokenHash;
            command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = newSession.refreshToken;
            command.Parameters.Add("@refreshes", NpgsqlDbType.Smallint).Value = DbValue(newSession.refreshes);
            command.Parameters.Add("@limit", NpgsqlDbType.Smallint).Value = DbValue(newSession.limit);
            command.Parameters.Add("@createdOn", InstantDbType).Value = newSession.createdOn;
            command.Parameters.Add("@sessionLifespan", NpgsqlDbType.Interval).Value = DbValue(newSession.sessionLifespan);
            command.Parameters.Add("@accessExpiration", InstantDbType).Value = newSession.accessExpiration;
            command.Parameters.Add("@sessionExpiration", InstantDbType).Value = newSession.sessionExpiration;
            command.Parameters.Add("@cutOff", InstantDbType).Value = DbValue(newSession.cutOff);
            command.Parameters.Add("@features", FeatureSetDbType).Value = (short)newSession.features;
            command.Parameters.Add("@securityStamp", SecurityStampDbType).Value = newSession.securityStamp;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(newSession.accountSecurityStamp);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                SessionRotationResult result = await ReadSessionRotationResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHashes(accountId, expectedOldAccessTokenHash, newAccessTokenHash));
                return null;
            }
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RotateActiveSession));
            return null;
        }
    }

    internal static async Task<SessionRotationResult> ReadSessionRotationResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new SessionRotationResult(SessionRotationStatus.Failed);
        }

        object value = dr[0];
        return new SessionRotationResult(ReadSessionRotationStatus(value));
    }

    internal static SessionRotationStatus ReadSessionRotationStatus(object? value)
    {
        if (value is null || value == DBNull.Value)
        {
            return SessionRotationStatus.Failed;
        }

        try
        {
            return value switch
            {
                SessionRotationStatus status => status,
                short status => Enum.IsDefined(typeof(SessionRotationStatus), (int)status) ? (SessionRotationStatus)status : SessionRotationStatus.Failed,
                int status => Enum.IsDefined(typeof(SessionRotationStatus), status) ? (SessionRotationStatus)status : SessionRotationStatus.Failed,
                long status => status >= int.MinValue && status <= int.MaxValue && Enum.IsDefined(typeof(SessionRotationStatus), (int)status)
                    ? (SessionRotationStatus)(int)status
                    : SessionRotationStatus.Failed,
                string status when Enum.TryParse(status, ignoreCase: true, out SessionRotationStatus parsed) => parsed,
                _ => SessionRotationStatus.Failed
            };
        }
        catch
        {
            return SessionRotationStatus.Failed;
        }
    }


    public async Task<CachedSessionTrustResult?> ValidateCachedSessionTrust(string accessTokenHash, Guid accountId, Guid securityStamp, Guid accountSecurityStamp)
    {
        try
        {
            const string procedure = ValidateCachedSessionTrustProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accessTokenHash",
                "accountId",
                "securityStamp",
                "accountSecurityStamp");

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@securityStamp", SecurityStampDbType).Value = securityStamp;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                CachedSessionTrustResult result = await ReadCachedSessionTrustResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHash(accountId, accessTokenHash));
                return null;
            }
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(ValidateCachedSessionTrust));
            return null;
        }
    }

    internal static async Task<CachedSessionTrustResult> ReadCachedSessionTrustResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new CachedSessionTrustResult(CachedSessionTrustStatus.Failed);
        }

        CachedSessionTrustStatus status = ReadCachedSessionTrustStatus(dr[0]);
        string? code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : null;
        Instant? accessExpiration = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetFieldValue<Instant>(2) : null;
        Instant? sessionExpiration = dr.FieldCount > 3 && !dr.IsDBNull(3) ? dr.GetFieldValue<Instant>(3) : null;
        Instant? cutOff = dr.FieldCount > 4 && !dr.IsDBNull(4) ? dr.GetFieldValue<Instant>(4) : null;
        Guid? currentSecurityStamp = dr.FieldCount > 5 && !dr.IsDBNull(5) ? dr.GetGuid(5) : null;
        Guid? currentAccountSecurityStamp = dr.FieldCount > 6 && !dr.IsDBNull(6) ? dr.GetGuid(6) : null;
        return new CachedSessionTrustResult(status, accessExpiration, sessionExpiration, cutOff, currentSecurityStamp, currentAccountSecurityStamp, code);
    }

    internal static CachedSessionTrustStatus ReadCachedSessionTrustStatus(object? value)
    {
        if (value is null || value == DBNull.Value)
        {
            return CachedSessionTrustStatus.Failed;
        }

        try
        {
            return value switch
            {
                CachedSessionTrustStatus status => status,
                short status => Enum.IsDefined(typeof(CachedSessionTrustStatus), (int)status) ? (CachedSessionTrustStatus)status : CachedSessionTrustStatus.Failed,
                int status => Enum.IsDefined(typeof(CachedSessionTrustStatus), status) ? (CachedSessionTrustStatus)status : CachedSessionTrustStatus.Failed,
                long status => status >= int.MinValue && status <= int.MaxValue && Enum.IsDefined(typeof(CachedSessionTrustStatus), (int)status)
                    ? (CachedSessionTrustStatus)(int)status
                    : CachedSessionTrustStatus.Failed,
                string status when Enum.TryParse(status, ignoreCase: true, out CachedSessionTrustStatus parsed) => parsed,
                _ => CachedSessionTrustStatus.Failed
            };
        }
        catch
        {
            return CachedSessionTrustStatus.Failed;
        }
    }

    /**
     * Expires a session at the provided point in time. A null value means "expire now"; hard deletion is reserved for future cleanup jobs.
     */
    public async Task<bool?> ExpireSession(string accessTokenHash, Instant? newExpiration)
    {
        try
        {
            const string procedure = ExpireSessionProcedure;
            Instant expiration = newExpiration ?? SystemClock.Instance.GetCurrentInstant();

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, "accessTokenHash", "expiration");

            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                bool result = await AccountRepo.ReadBooleanProcedureResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccessTokenHashExpiration(accessTokenHash, expiration));
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(ExpireSession));
            return null;
        }
    }


    public async Task<DbCommandResult?> LogoutCurrentSession(Guid accountId, string accessTokenHash, Guid accountSecurityStamp)
    {
        try
        {
            const string procedure = LogoutCurrentSessionProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accessTokenHash",
                "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accessTokenHash", AccessTokenHashDbType).Value = accessTokenHash;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                DbCommandResult result = await ReadDbCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHash(accountId, accessTokenHash));
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(LogoutCurrentSession), RepositoryLogScopes.AccountTokenHash(accountId, accessTokenHash));
            return null;
        }
    }

    public async Task<AccountStampRotationResult?> LogoutAllSessions(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            const string procedure = LogoutAllSessionsProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountStampRotationResult result = await ReadAccountStampRotationResultAsync(dr);
                await dr.DisposeAsync();
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
            LogRepositoryFailure(ex, nameof(LogoutAllSessions), new { accountId });
            return null;
        }
    }



    public async Task<IReadOnlyList<AccountSessionSummary>?> ListActiveSessions(Guid accountId, Guid accountSecurityStamp, string currentAccessTokenHash)
    {
        try
        {
            const string procedure = ListActiveSessionsProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "currentAccessTokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);
            command.Parameters.Add("@currentAccessTokenHash", AccessTokenHashDbType).Value = currentAccessTokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                IReadOnlyList<AccountSessionSummary> result = await ReadAccountSessionSummariesAsync(dr);
                await dr.DisposeAsync();
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
            LogRepositoryFailure(ex, nameof(ListActiveSessions), new { accountId });
            return null;
        }
    }

    public async Task<DbCommandResult?> RevokeSessionForAccount(Guid accountId, Guid targetSessionId, Guid accountSecurityStamp, string currentAccessTokenHash)
    {
        try
        {
            const string procedure = RevokeSessionForAccountProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                procedure,
                conn,
                tran,
                "accountId",
                "targetSessionId",
                "accountSecurityStamp",
                "currentAccessTokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@targetSessionId", SessionIdDbType).Value = targetSessionId;
            command.Parameters.Add("@accountSecurityStamp", SecurityStampDbType).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);
            command.Parameters.Add("@currentAccessTokenHash", AccessTokenHashDbType).Value = currentAccessTokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                DbCommandResult result = await ReadDbCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, new { accountId, targetSessionId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RevokeSessionForAccount), new { accountId, targetSessionId });
            return null;
        }
    }

    internal static async Task<IReadOnlyList<AccountSessionSummary>> ReadAccountSessionSummariesAsync(NpgsqlDataReader dr)
    {
        var sessions = new List<AccountSessionSummary>();
        while (await dr.ReadAsync())
        {
            sessions.Add(new AccountSessionSummary(
                dr.GetGuid(0),
                dr.GetFieldValue<Instant>(1),
                dr.GetFieldValue<Instant>(2),
                dr.GetFieldValue<Instant>(3),
                dr.FieldCount > 4 && !dr.IsDBNull(4) ? (FeatureSet)dr.GetInt16(4) : FeatureSet.basic,
                dr.FieldCount > 5 && !dr.IsDBNull(5) && dr.GetBoolean(5)));
        }

        return sessions;
    }

    internal static async Task<DbCommandResult> ReadDbCommandResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new DbCommandResult(false, "NO_RESULT");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1)
            ? dr.GetString(1)
            : "UNKNOWN";

        return new DbCommandResult(result, code);
    }

    internal static async Task<AccountStampRotationResult> ReadAccountStampRotationResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountStampRotationResult(false, "NO_RESULT", null);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1)
            ? dr.GetString(1)
            : "UNKNOWN";
        Guid? accountSecurityStamp = dr.FieldCount > 2 && !dr.IsDBNull(2)
            ? dr.GetGuid(2)
            : null;

        return new AccountStampRotationResult(result, code, accountSecurityStamp);
    }

    public async Task<bool?> UpdateRefreshToken(Guid accountId, byte[] refreshToken)
    {
        try
        {
            const string procedure = UpdateRefreshTokenProcedure;

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, "accountId", "refreshToken");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = refreshToken;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                bool result = await AccountRepo.ReadBooleanProcedureResultAsync(dr);
                await dr.DisposeAsync();
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
            LogRepositoryFailure(ex, nameof(UpdateRefreshToken));
            return null;
        }
    }

    internal static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
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
