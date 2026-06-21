using System.Data;

using Npgsql;
using NpgsqlTypes;
using NodaTime;

using treehammock.Models.Account;
using treehammock.Models.Authentication;
using treehammock.Rigging.Database;
using treehammock.DataLayer.Account;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.Entities;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace treehammock.Repos;

public enum CredentialLookupStatus
{
    Found,
    NotFound,
    Failed
}

public sealed record CredentialLookupResult
{
    private CredentialLookupResult(CredentialLookupStatus status, IntraAccount? account = null)
    {
        if (status == CredentialLookupStatus.Found && account == null)
        {
            throw new ArgumentNullException(nameof(account), "Found credential lookups must carry an account.");
        }

        if (status != CredentialLookupStatus.Found && account != null)
        {
            throw new ArgumentException("Only found credential lookups may carry an account.", nameof(account));
        }

        Status = status;
        Account = account;
    }

    public CredentialLookupStatus Status { get; }
    public IntraAccount? Account { get; }
    public bool Succeeded => Status == CredentialLookupStatus.Found;

    public static CredentialLookupResult Found(IntraAccount account) => new(CredentialLookupStatus.Found, account);
    public static CredentialLookupResult NotFound() => new(CredentialLookupStatus.NotFound);
    public static CredentialLookupResult Failed() => new(CredentialLookupStatus.Failed);
}


public enum TwoFactorDetailsLookupStatus
{
    Found,
    NotConfigured,
    Failed
}

public sealed record TwoFactorDetailsLookupResult
{
    private TwoFactorDetailsLookupResult(TwoFactorDetailsLookupStatus status, TwoFactorDetails? details = null)
    {
        if (status == TwoFactorDetailsLookupStatus.Found && details == null)
        {
            throw new ArgumentNullException(nameof(details), "Found two-factor detail lookups must carry details.");
        }

        if (status != TwoFactorDetailsLookupStatus.Found && details != null)
        {
            throw new ArgumentException("Only found two-factor detail lookups may carry details.", nameof(details));
        }

        Status = status;
        Details = details;
    }

    public TwoFactorDetailsLookupStatus Status { get; }
    public TwoFactorDetails? Details { get; }
    public bool Succeeded => Status == TwoFactorDetailsLookupStatus.Found;

    public static TwoFactorDetailsLookupResult Found(TwoFactorDetails details) => new(TwoFactorDetailsLookupStatus.Found, details);
    public static TwoFactorDetailsLookupResult NotConfigured() => new(TwoFactorDetailsLookupStatus.NotConfigured);
    public static TwoFactorDetailsLookupResult Failed() => new(TwoFactorDetailsLookupStatus.Failed);
}

public sealed record AccountVerificationResendResult(bool Result, string Code, string? EmailAddress);

public sealed record TwoFactorChallengeCommandResult(
    bool Result,
    string Code,
    short ChallengeAttempts,
    short ChallengeResends,
    Instant? ChallengeExpiration,
    Instant? NextChallengeAllowedAt);

public sealed record TwoFactorSetupCommandResult(
    bool Result,
    string Code,
    short? TwoFactorIndex,
    Instant? Expiration);

public sealed record TwoFactorSetupVerificationCommandResult(
    bool Result,
    string Code,
    short Attempts,
    Instant? Expiration);

public sealed record TwoFactorMethodRemovalCommandResult(
    bool Result,
    string Code,
    TwoFactorAuthMethod RemovedMethod,
    IReadOnlyList<TwoFactorAuthMethod> TwoFactorAuthMethods,
    IReadOnlyList<TwoFactorAuthConfiguration> AvailableTwoFactorAuthConfigurations);

public interface IAccountRepo
{
    Task<(long?, HttpMessage, string?)> SetupAccount(Account single, string verifyKeyHash, Period verificationExpiration, AccountSetupAction step);
    Task<bool?> StartAccountVerification(Guid accountGuid, long? verificationIndex);
    Task<AccountVerificationResendResult?> ResendAccountVerification(string emailAddress, string verifyKeyHash, Period verificationExpiration);
    Task<AccountVerification?> VerifyAccountForUse(string verifyKey);
    Task<bool?> AccountPassedVerification(AccountVerification record);
    Task<bool?> AccountVerificationExpired(AccountVerification record);
    Task<CredentialLookupResult> GetCredentials(AuthenticateLogin single, AccountLoginAction action);
    Task<TwoFactorDetailsLookupResult> GetTwoFactorDetails(Guid accountId);
    Task<TwoFactorSetupCommandResult?> BeginTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        Instant createdOn,
        Instant expiration,
        string? emailAddress,
        string? phoneNumber,
        string? phoneCountryCode,
        string? authId,
        bool required);
    Task<DbCommandResult?> CancelTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash);
    Task<TwoFactorSetupVerificationCommandResult?> VerifyTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        short maxAttempts,
        Instant moment);
    Task<TwoFactorMethodRemovalCommandResult?> RemoveTwoFactorMethod(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        Instant moment);
    Task<bool?> SetLockOut(Guid accountGuid, short? loginFailuress);
    Task<bool?> RemoveLockOut(Guid accountGuid);
    Task<bool?> SetLoginFailures(Guid accountGuid, int failures);
    Task<bool?> SuccessfulLogin(Guid accountId, Guid accountSecurityStamp);
    Task<bool?> RotateAccountSecurityStamp(Guid accountId);
    Task<AccountAdjustResult?> ModifyUsername(Guid accountId, Guid accountSecurityStamp, string username);
    Task<AccountAdjustResult?> RequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress, string verifyKeyHash, Instant expiration);
    Task<AccountAdjustResult?> CancelEmailChangeRequest(Guid accountId, Guid accountSecurityStamp, string verifyKeyHash);
    Task<AccountAdjustResult?> CompleteEmailChange(string verifyKeyHash);
    Task<AccountDeleteCommandResult?> RequestAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string? passPhraseHash,
        string deleteTokenHash,
        Instant expiration,
        Period requestCooldown,
        Period requestWindow,
        short maxRequestsPerWindow);
    Task<AccountDeleteCommandResult?> CancelAccountDeleteRequest(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteTokenHash);
    Task<AccountDeleteCommandResult?> VerifyDeleteAccountToken(string deleteTokenHash);
    Task<AccountDeleteCommandResult?> FinalizeAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteTokenHash,
        string? passPhrase,
        short maxFailedFinalizeAttempts,
        Period finalizeLockout);
    Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant moment);
    Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant moment);
    Task<AccountViewResult?> ViewAccount(Guid accountId, Guid accountSecurityStamp);
    public Task<bool?> Set2FASession(Guid accountId, Guid accountSecurityStamp, short? twoAuthUsage, string preAuthAccessTokenHash);
    Task<bool?> BeginTwoFactorSession(Guid accountId, Guid accountSecurityStamp, short? twoAuthUsage, string preAuthAccessTokenHash, Instant createdOn, Instant expiration);
    Task<TwoFactorChallengeCommandResult?> RecordTwoFactorChallengeIssued(
        Guid accountId,
        Guid accountSecurityStamp,
        string expectedPreAuthAccessTokenHash,
        TwoFactorAuthMethod challengedMethod,
        short chosenDestination,
        string? challengeCodeHash,
        string? challengeProviderTransactionId,
        Instant challengeExpiration,
        Instant nextChallengeAllowedAt,
        short maxResends,
        Instant moment,
        TwoFactorAuthConfiguration? selectedConfiguration = null,
        TwoFactorSessionState? state = null,
        IReadOnlyCollection<TwoFactorAuthMethod>? requiredMethods = null,
        IReadOnlyCollection<TwoFactorAuthMethod>? completedMethods = null,
        TwoFactorAuthMethod? currentExpectedMethod = null,
        Instant? selectedAt = null);
    Task<TwoFactorChallengeCommandResult?> CancelTwoFactorChallengeIssued(
        Guid accountId,
        Guid accountSecurityStamp,
        string expectedPreAuthAccessTokenHash,
        TwoFactorAuthMethod challengedMethod,
        short chosenDestination,
        string? challengeCodeHash,
        string? challengeProviderTransactionId,
        Instant moment);
    Task<TwoFactorChallengeCommandResult?> RecordTwoFactorChallengeFailure(
        Guid accountId,
        Guid accountSecurityStamp,
        string expectedPreAuthAccessTokenHash,
        short maxAttempts,
        Instant moment);
    Task<bool?> IsPendingTwoFactorSessionCurrent(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp);
    Task<bool?> SuccessfulTwoFactorAuth(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp);
    Task<DbCommandResult?> PromoteTwoFactorNewLogin(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp, string newAccessTokenHash, Session newSession);
    Task<DbCommandResult?> PromoteTwoFactorRotationLogin(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp, string expectedOldAccessTokenHash, string newAccessTokenHash, Session newSession);
}

public class AccountRepo : IAccountRepo
{
    internal const string SetupAccountEmailFunction = "setup_account_email";
    internal const string SetupAccountBothFunction = "setup_account_both";
    internal const string StartVerifyAccountFunction = "start_verify_account";
    internal const string ResendVerifyAccountFunction = "resend_verify_account";
    internal const string VerifyAccountForUseProcedure = "verify_account_for_use";
    internal const string CompleteVerifyAccountProcedure = "complete_verify_account";
    internal const string ExpireVerifyAccountProcedure = "expire_verify_account";
    internal const string RotateAccountSecurityStampProcedure = "rotate_account_security_stamp";
    internal const string BeginTwoFactorAuthDetailFunction = "begin_twofactor_auth_detail";
    internal const string BeginTwoFactorSetupFunction = "begin_twofactor_setup";
    internal const string CancelTwoFactorSetupFunction = "cancel_twofactor_setup";
    internal const string VerifyTwoFactorSetupFunction = "verify_twofactor_setup";
    internal const string RemoveTwoFactorMethodFunction = "remove_twofactor_method";
    internal const string RecordTwoFactorChallengeIssuedFunction = "record_twofactor_challenge_issued";
    internal const string CancelTwoFactorChallengeIssuedFunction = "cancel_twofactor_challenge_issued";
    internal const string RecordTwoFactorChallengeFailureFunction = "record_twofactor_challenge_failure";
    internal const string PromoteTwoFactorNewLoginFunction = "promote_twofactor_new_login";
    internal const string PromoteTwoFactorRotationLoginFunction = "promote_twofactor_rotation_login";
    internal const string ViewAccountFunction = "view_account";
    internal const string EditAccountUsernameFunction = "edit_account_username";
    internal const string RequestAccountEmailChangeFunction = "request_account_email_change";
    internal const string CancelAccountEmailChangeRequestFunction = "cancel_account_email_change_request";
    internal const string CompleteAccountEmailChangeFunction = "complete_account_email_change";
    internal const string PurgeExpiredAccountEmailChangeRequestsFunction = "purge_expired_account_email_change_requests";
    internal const string RequestAccountDeleteFunction = "request_account_delete";
    internal const string CancelAccountDeleteRequestFunction = "cancel_account_delete_request";
    internal const string VerifyAccountDeleteTokenFunction = "verify_account_delete_token";
    internal const string PrepareAccountDeleteFinalizeFunction = "prepare_account_delete_finalize";
    internal const string CommitAccountDeleteFinalizeFunction = "commit_account_delete_finalize";
    internal const string PurgeExpiredDeleteStandbyFunction = "purge_expired_delete_standby";

    internal const NpgsqlDbType WebKeyDbType = NpgsqlDbType.Text;
    internal const NpgsqlDbType HashedPasswordDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType SaltOneDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType SivDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType NonceDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType RefreshTokenDbType = NpgsqlDbType.Bytea;
    internal const NpgsqlDbType InstantDbType = NpgsqlDbType.TimestampTz;

    private readonly StorageContext _activeDatabase;
    private readonly JWTSettings _jwtSettings;
    private readonly ILogger<AccountRepo> _logger;
    private readonly IUserSecretHasher _userSecretHasher;

    public AccountRepo(
        StorageContext database,
        IOptions<JWTSettings> jwtSettings,
        ILogger<AccountRepo> logger,
        IUserSecretHasher userSecretHasher)
    {
        _activeDatabase = database;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
        _userSecretHasher = userSecretHasher;
    }

    internal static IntraAccount MapCredentialColumns(
        Guid accountId,
        byte[] hashedPassword,
        string webKey,
        byte[]? refreshToken,
        short refreshes,
        short limit,
        Instant createdOn,
        Period? lifespan,
        byte[] saltOne,
        byte[] siv,
        byte[] nonce,
        Instant? unlockWhen,
        short loginFailures,
        VerificationStatus verifyStatus,
        FeatureSet features,
        string? twoFactorAccessToken,
        TwoFactorAuthMethod twoFactorAuthMethod,
        short twoAuthUsage,
        Instant? cutOff = null,
        string? activeAccessTokenHash = null,
        Guid? accountSecurityStamp = null)
    {
        return new IntraAccount(
            accountId: accountId,
            hashedPassword: EnsureNonEmptyBytes(hashedPassword, nameof(IntraAccount.hashedPassword)),
            webKey: webKey,
            refreshToken: refreshToken,
            refreshes: refreshes,
            limit: limit,
            createdOn: createdOn,
            lifespan: lifespan,
            saltOne: EnsureByteLength(saltOne, AccountCryptoSizes.SaltOneBytes, nameof(IntraAccount.saltOne)),
            siv: EnsureByteLength(siv, AccountCryptoSizes.SivBytes, nameof(IntraAccount.siv)),
            nonce: EnsureByteLength(nonce, AccountCryptoSizes.NonceBytes, nameof(IntraAccount.nonce)),
            unlockWhen: unlockWhen,
            loginFailures: loginFailures,
            verifyStatus: verifyStatus,
            features: features,
            twoFactorAccessToken: twoFactorAccessToken,
            twoFactorAuthMethod: twoFactorAuthMethod,
            twoAuthUsage: twoAuthUsage,
            cutOff: cutOff,
            activeAccessTokenHash: activeAccessTokenHash,
            accountSecurityStamp: accountSecurityStamp);
    }


    internal static byte[] EnsureByteLength(byte[] value, int expectedLength, string fieldName)
    {
        if (value.Length != expectedLength)
        {
            throw new DataException($"{fieldName} expected {expectedLength} bytes but received {value.Length} bytes.");
        }

        return value;
    }

    internal static byte[] EnsureNonEmptyBytes(byte[] value, string fieldName)
    {
        if (value.Length == 0)
        {
            throw new DataException($"{fieldName} cannot be empty.");
        }

        return value;
    }


    private static byte[] ReadVariableBytes(NpgsqlDataReader reader, int ordinal, string fieldName)
    {
        if (reader.IsDBNull(ordinal))
        {
            throw new DataException($"{fieldName} cannot be null.");
        }

        byte[] value = reader.GetFieldValue<byte[]>(ordinal);
        if (value.Length <= 0)
        {
            throw new DataException($"{fieldName} cannot be empty.");
        }

        return value;
    }


    private static byte[] ReadFixedBytes(NpgsqlDataReader reader, int ordinal, int expectedLength, string fieldName)
    {
        if (reader.IsDBNull(ordinal))
        {
            throw new DataException($"{fieldName} cannot be null.");
        }

        byte[] value = reader.GetFieldValue<byte[]>(ordinal);
        if (value.Length != expectedLength)
        {
            throw new DataException($"{fieldName} expected {expectedLength} bytes but received {value.Length} bytes.");
        }

        return value;
    }

    private static string? ReadActiveAccessTokenHash(NpgsqlDataReader reader, byte[]? refreshToken)
    {
        const int ActiveAccessTokenHashOrdinal = 20;

        if (reader.FieldCount <= ActiveAccessTokenHashOrdinal)
        {
            if (refreshToken is not null)
            {
                throw new DataException("Credential lookup result for an active account session must include active_access_token_hash.");
            }

            return null;
        }

        if (reader.IsDBNull(ActiveAccessTokenHashOrdinal))
        {
            if (refreshToken is not null)
            {
                throw new DataException("Credential lookup result for an active account session returned a null active_access_token_hash.");
            }

            return null;
        }

        return reader.GetString(ActiveAccessTokenHashOrdinal);
    }

    private static Instant? ReadCredentialCutOff(NpgsqlDataReader reader)
    {
        const int CutOffOrdinal = 18;

        if (reader.FieldCount <= CutOffOrdinal)
        {
            throw new DataException("Credential lookup result must include account cut_off.");
        }

        return reader.IsDBNull(CutOffOrdinal) ? null : reader.GetFieldValue<Instant>(CutOffOrdinal);
    }

    private static Guid ReadCredentialAccountSecurityStamp(NpgsqlDataReader reader)
    {
        const int AccountSecurityStampOrdinal = 19;

        if (reader.FieldCount <= AccountSecurityStampOrdinal || reader.IsDBNull(AccountSecurityStampOrdinal))
        {
            throw new DataException("Credential lookup result must include account_security_stamp.");
        }

        Guid accountSecurityStamp = reader.GetGuid(AccountSecurityStampOrdinal);
        if (accountSecurityStamp == Guid.Empty)
        {
            throw new DataException("Credential lookup result returned an empty account_security_stamp.");
        }

        return accountSecurityStamp;
    }

    public async Task<(long?, HttpMessage, string?)> SetupAccount(Account single, string verifyKeyHash, Period verificationExpiration, AccountSetupAction step)
    {
        try
        {
            string functionName = step == AccountSetupAction.BOTH
                ? SetupAccountBothFunction
                : SetupAccountEmailFunction;

            string[] parameterNames = step == AccountSetupAction.BOTH
                ? new[] { "accountId", "username", "emailAddress", "webKey", "hashedPassword", "saltOne", "siv", "nonce", "country", "verifyKeyHash", "createdOn", "verificationExpiration" }
                : new[] { "accountId", "emailAddress", "webKey", "hashedPassword", "saltOne", "siv", "nonce", "country", "verifyKeyHash", "createdOn", "verificationExpiration" };

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(functionName, conn, tran, parameterNames);

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = single.accountId;
            if (step == AccountSetupAction.BOTH)
            {
                command.Parameters.Add("@username", NpgsqlDbType.Text).Value = single.username!;
            }

            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = single.emailAddress;
            command.Parameters.Add("@webKey", WebKeyDbType).Value = single.webKey;
            command.Parameters.Add("@hashedPassword", HashedPasswordDbType).Value = single.hashedPassword;
            command.Parameters.Add("@saltOne", SaltOneDbType).Value = single.saltOne;
            command.Parameters.Add("@siv", SivDbType).Value = single.siv;
            command.Parameters.Add("@nonce", NonceDbType).Value = single.nonce;
            command.Parameters.Add("@country", NpgsqlDbType.Smallint).Value = (short)single.country;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;
            command.Parameters.Add("@createdOn", InstantDbType).Value = single.createdOn;
            command.Parameters.Add("@verificationExpiration", NpgsqlDbType.Interval).Value = verificationExpiration;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    long? verificationIndex = dr.IsDBNull(0) ? null : dr.GetInt64(0);
                    HttpMessage outcome = (HttpMessage)dr.GetInt16(1);
                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return (verificationIndex, outcome, null);
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
                return (null, HttpMessage.ACCOUNT_CREATION_FAILED, null);
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.AccountSetup(step, single.accountId, single.emailAddress, single.username));
                return (null, HttpMessage.ACCOUNT_CREATION_FAILED, ex.StackTrace);
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(SetupAccount));
            return (null, HttpMessage.ACCOUNT_CREATION_FAILED, null);
        }
    }

    public async Task<bool?> StartAccountVerification(Guid accountGuid, long? verificationIndex)
    {
        try
        {
            if (verificationIndex is null)
            {
                return false;
            }

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(StartVerifyAccountFunction, conn, tran, "accountGuid", "verificationIndex");

            command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;
            command.Parameters.Add("@verificationIndex", NpgsqlDbType.Bigint).Value = verificationIndex.Value;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                bool result = await ReadBooleanProcedureResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountGuid, verificationIndex });
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(StartAccountVerification));
            return null;
        }
    }

    public async Task<AccountVerificationResendResult?> ResendAccountVerification(string emailAddress, string verifyKeyHash, Period verificationExpiration)
    {
        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(ResendVerifyAccountFunction, conn, tran, "emailAddress", "verifyKeyHash", "verificationExpiration");

            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = emailAddress;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;
            command.Parameters.Add("@verificationExpiration", NpgsqlDbType.Interval).Value = verificationExpiration;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    bool result = !dr.IsDBNull(0) && dr.GetBoolean(0);
                    string code = dr.IsDBNull(1) ? "UNKNOWN" : dr.GetString(1);
                    string? targetEmailAddress = dr.IsDBNull(2) ? null : dr.GetString(2);
                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return new AccountVerificationResendResult(result, code, targetEmailAddress);
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
                return new AccountVerificationResendResult(false, "NO_RESULT", null);
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.EmailAddressScope(emailAddress));
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(ResendAccountVerification));
            return null;
        }
    }

    public async Task<AccountVerification?> VerifyAccountForUse(string verifyKey)
    {
        try
        {
            string verifyKeyHash = AccountVerificationTokenUtility.HashToken(verifyKey);

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(VerifyAccountForUseProcedure, conn, tran, "verifyKeyHash");

            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                if (await dr.ReadAsync())
                {
                    Instant? sentWhen = dr.IsDBNull(3) ? null : dr.GetFieldValue<Instant>(3);
                    Period? expiration = dr.IsDBNull(4) ? null : dr.GetFieldValue<Period>(4);
                    var verification = new AccountVerification(dr.GetGuid(0), dr.GetString(1), (VerificationStatus)dr.GetInt16(2), sentWhen, expiration);
                    await dr.DisposeAsync();
                    await tran.CommitAsync();
                    return verification;
                }

                await dr.DisposeAsync();
                await tran.CommitAsync();
                return null;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText);
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(VerifyAccountForUse));
            return null;
        }
    }

    public async Task<bool?> AccountPassedVerification(AccountVerification record)
    {
        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(CompleteVerifyAccountProcedure, conn, tran, "accountId", "verifyKeyHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = record.accountId;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = record.verifyKey;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                bool result = await ReadBooleanProcedureResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { record.accountId });
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(AccountPassedVerification));
            return null;
        }
    }

    public async Task<bool?> AccountVerificationExpired(AccountVerification record)
    {
        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(ExpireVerifyAccountProcedure, conn, tran, "accountId", "verifyKeyHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = record.accountId;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = record.verifyKey;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                bool result = await ReadBooleanProcedureResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { record.accountId });
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(AccountVerificationExpired));
            return null;
        }
    }

    public async Task<CredentialLookupResult> GetCredentials(AuthenticateLogin single, AccountLoginAction action)
    {
        try
        {
            string functionName;
            string[] parameterNames;

            if (action == AccountLoginAction.BOTH)
            {
                functionName = "check_account_both_creds";
                parameterNames = new[] { "username", "emailAddress" };
            }
            else if (action == AccountLoginAction.USERNAME)
            {
                functionName = "check_account_username_creds";
                parameterNames = new[] { "username" };
            }
            else if (action == AccountLoginAction.EMAIL)
            {
                functionName = "check_account_emailaddress_creds";
                parameterNames = new[] { "emailAddress" };
            }
            else
            {
                return CredentialLookupResult.Failed();
            }

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(functionName, conn, tran, parameterNames);

            if (action == AccountLoginAction.BOTH || action == AccountLoginAction.USERNAME)
            {
                command.Parameters.Add("@username", NpgsqlDbType.Text).Value = single.username;
            }

            if (action == AccountLoginAction.BOTH || action == AccountLoginAction.EMAIL)
            {
                command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = single.emailAddress;
            }

            try
            {
                CredentialLookupResult result;
                await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync())
                {
                    if (await dr.ReadAsync())
                    {
                        byte[] hashedPassword = ReadVariableBytes(dr, 1, nameof(IntraAccount.hashedPassword));

                        byte[]? refreshToken = null;
                        if (!await dr.IsDBNullAsync(3))
                        {
                            refreshToken = ReadFixedBytes(dr, 3, _jwtSettings.RefreshTokenBytes, nameof(IntraAccount.refreshToken));
                        }

                        Period? lifespan = dr.IsDBNull(7) ? null : dr.GetFieldValue<Period>(7);

                        byte[] saltOneBuffer = ReadFixedBytes(dr, 8, AccountCryptoSizes.SaltOneBytes, nameof(IntraAccount.saltOne));
                        byte[] sivBuffer = ReadFixedBytes(dr, 9, AccountCryptoSizes.SivBytes, nameof(IntraAccount.siv));
                        byte[] nonceBuffer = ReadFixedBytes(dr, 10, AccountCryptoSizes.NonceBytes, nameof(IntraAccount.nonce));

                        Instant? unlockWhen = dr.IsDBNull(11) ? null : dr.GetFieldValue<Instant>(11);
                        string? twoFactorAccessToken = dr.IsDBNull(15) ? null : dr.GetString(15);
                        Instant? cutOff = ReadCredentialCutOff(dr);
                        Guid accountSecurityStamp = ReadCredentialAccountSecurityStamp(dr);
                        string? activeAccessTokenHash = ReadActiveAccessTokenHash(dr, refreshToken);

                        IntraAccount mapped = MapCredentialColumns(
                            accountId: dr.GetGuid(0),
                            hashedPassword: hashedPassword,
                            webKey: dr.GetString(2),
                            refreshToken: refreshToken,
                            refreshes: dr.GetInt16(4),
                            limit: dr.GetInt16(5),
                            createdOn: dr.GetFieldValue<Instant>(6),
                            lifespan: lifespan,
                            saltOne: saltOneBuffer,
                            siv: sivBuffer,
                            nonce: nonceBuffer,
                            unlockWhen: unlockWhen,
                            loginFailures: dr.GetInt16(12),
                            verifyStatus: (VerificationStatus)dr.GetInt16(13),
                            features: (FeatureSet)dr.GetInt16(14),
                            twoFactorAccessToken: twoFactorAccessToken,
                            twoFactorAuthMethod: (TwoFactorAuthMethod)dr.GetInt16(16),
                            twoAuthUsage: dr.GetInt16(17),
                            cutOff: cutOff,
                            activeAccessTokenHash: activeAccessTokenHash,
                            accountSecurityStamp: accountSecurityStamp);

                        result = CredentialLookupResult.Found(mapped);
                    }
                    else
                    {
                        result = CredentialLookupResult.NotFound();
                    }
                }

                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { action });
                return CredentialLookupResult.Failed();
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetCredentials));
            return CredentialLookupResult.Failed();
        }
    }

    public Period FindLockoutPeriod(short? loginFailures)
    {
        PeriodBuilder lockoutPeriod = new PeriodBuilder();
        if (loginFailures != null) 
        {
            lockoutPeriod.Hours = (long)((loginFailures + 1) * 2);
        }
        return lockoutPeriod.Build();
    }


    public async Task<TwoFactorDetailsLookupResult> GetTwoFactorDetails(Guid accountId)
    {
        try
        {
            var methods = new List<TwoFactorAuthMethod>();
            var userAuthIds = new List<string>();
            var phoneNumbers = new List<string>();
            var phoneCountryCodes = new List<string>();
            var emailAddresses = new List<string>();

            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("get_twofactor_details", conn, tran, "accountId"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            while (await dr.ReadAsync())
                            {
                                var method = (TwoFactorAuthMethod)dr.GetInt16(0);
                                methods.Add(method);

                                switch (method)
                                {
                                    case TwoFactorAuthMethod.AUTHENTICATOR_APP:
                                        AddIfNotBlank(userAuthIds, ReadOptionalString(dr, 1));
                                        break;
                                    case TwoFactorAuthMethod.SMS_KEY:
                                        AddIfNotBlank(phoneNumbers, ReadOptionalString(dr, 2));
                                        AddIfNotBlank(phoneCountryCodes, ReadOptionalString(dr, 3));
                                        break;
                                    case TwoFactorAuthMethod.EMAIL:
                                        AddIfNotBlank(emailAddresses, ReadOptionalString(dr, 4));
                                        break;
                                }
                            }

                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            return TwoFactorDetailsLookupResult.Failed();
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            if (methods.Count == 0)
            {
                return TwoFactorDetailsLookupResult.NotConfigured();
            }

            return TwoFactorDetailsLookupResult.Found(new TwoFactorDetails(methods, userAuthIds, phoneNumbers, phoneCountryCodes, emailAddresses));
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(GetTwoFactorDetails));
            return TwoFactorDetailsLookupResult.Failed();
        }
    }

    private static string ReadOptionalString(NpgsqlDataReader reader, int ordinal)
    {
        return reader.IsDBNull(ordinal) ? string.Empty : reader.GetString(ordinal);
    }

    private static void AddIfNotBlank(List<string> values, string value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            values.Add(value);
        }
    }

    public async Task<bool?> SetLockOut(Guid accountGuid, short? loginFailures)
    {
        try
        {
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("set_account_lockout", conn, tran, "accountGuid", "expiration"))
                    {
                        command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;
                        command.Parameters.Add("@expiration", NpgsqlDbType.Interval).Value = FindLockoutPeriod(loginFailures);

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(SetLockOut));
            return null;
        }
    }

    public async Task<bool?> RemoveLockOut(Guid accountGuid)
    {
        try
        {
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                   await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("remove_account_lockout", conn, tran, "accountGuid"))
                   {
                        command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RemoveLockOut));
            return null;
        }
    }

    public async Task<bool?> SetLoginFailures(Guid accountGuid, int failures)
    {
        try
        {
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("set_account_login_failures", conn, tran, "accountGuid", "failures"))
                    {
                        command.Parameters.Add("@accountGuid", NpgsqlDbType.Uuid).Value = accountGuid;
                        command.Parameters.Add("@failures", NpgsqlDbType.Smallint).Value = (short)Math.Clamp(failures, short.MinValue, short.MaxValue);

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(SetLoginFailures));
            return null;
        }
    }

    public async Task<AccountAdjustResult?> ModifyUsername(Guid accountId, Guid accountSecurityStamp, string username)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                EditAccountUsernameFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "username");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@username", NpgsqlDbType.Text).Value = username;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.AccountUsername(accountId, username));
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(ModifyUsername), RepositoryLogScopes.AccountUsername(accountId, username));
            return null;
        }
    }

    public async Task<AccountAdjustResult?> RequestEmailChange(
        Guid accountId,
        Guid accountSecurityStamp,
        string newEmailAddress,
        string verifyKeyHash,
        Instant expiration)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RequestAccountEmailChangeFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "newEmailAddress",
                "verifyKeyHash",
                "expiration");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@newEmailAddress", NpgsqlDbType.Text).Value = newEmailAddress;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, RepositoryLogScopes.AccountEmailAddress(accountId, newEmailAddress));
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RequestEmailChange), RepositoryLogScopes.AccountEmailAddress(accountId, newEmailAddress));
            return null;
        }
    }

    public async Task<AccountAdjustResult?> CancelEmailChangeRequest(
        Guid accountId,
        Guid accountSecurityStamp,
        string verifyKeyHash)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CancelAccountEmailChangeRequestFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "verifyKeyHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr);
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
            LogRepositoryFailure(ex, nameof(CancelEmailChangeRequest), new { accountId });
            return null;
        }
    }

    public async Task<AccountAdjustResult?> CompleteEmailChange(string verifyKeyHash)
    {
        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CompleteAccountEmailChangeFunction,
                conn,
                tran,
                "verifyKeyHash");

            command.Parameters.Add("@verifyKeyHash", NpgsqlDbType.Text).Value = verifyKeyHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountAdjustResult result = await ReadAccountAdjustResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText);
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CompleteEmailChange));
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> RequestAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string? passPhraseHash,
        string deleteTokenHash,
        Instant expiration,
        Period requestCooldown,
        Period requestWindow,
        short maxRequestsPerWindow)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RequestAccountDeleteFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "passPhraseHash",
                "deleteTokenHash",
                "expiration",
                "requestCooldown",
                "requestWindow",
                "maxRequestsPerWindow");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@passPhraseHash", NpgsqlDbType.Text).Value = DbValue(passPhraseHash);
            command.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;
            command.Parameters.Add("@requestCooldown", NpgsqlDbType.Interval).Value = requestCooldown;
            command.Parameters.Add("@requestWindow", NpgsqlDbType.Interval).Value = requestWindow;
            command.Parameters.Add("@maxRequestsPerWindow", NpgsqlDbType.Smallint).Value = maxRequestsPerWindow;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountDeleteCommandResult result = await ReadAccountDeleteRequestResultAsync(dr);
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
            LogRepositoryFailure(ex, nameof(RequestAccountDelete), new { accountId });
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> CancelAccountDeleteRequest(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteTokenHash)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CancelAccountDeleteRequestFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "deleteTokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountDeleteCommandResult result = await ReadAccountDeleteRequestResultAsync(dr);
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
            LogRepositoryFailure(ex, nameof(CancelAccountDeleteRequest), new { accountId });
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> VerifyDeleteAccountToken(string deleteTokenHash)
    {
        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                VerifyAccountDeleteTokenFunction,
                conn,
                tran,
                "deleteTokenHash");

            command.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountDeleteCommandResult result = await ReadAccountDeleteVerifyResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText);
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(VerifyDeleteAccountToken));
            return null;
        }
    }

    public async Task<AccountDeleteCommandResult?> FinalizeAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteTokenHash,
        string? passPhrase,
        short maxFailedFinalizeAttempts,
        Period finalizeLockout)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();

            try
            {
                await using NpgsqlCommand prepareCommand = RepositoryCommands.CreateFunctionCommand(
                    PrepareAccountDeleteFinalizeFunction,
                    conn,
                    tran,
                    "accountId",
                    "accountSecurityStamp",
                    "deleteTokenHash",
                    "maxFailedFinalizeAttempts",
                    "finalizeLockout");

                prepareCommand.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
                prepareCommand.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
                prepareCommand.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;
                prepareCommand.Parameters.Add("@maxFailedFinalizeAttempts", NpgsqlDbType.Smallint).Value = maxFailedFinalizeAttempts;
                prepareCommand.Parameters.Add("@finalizeLockout", NpgsqlDbType.Interval).Value = finalizeLockout;

                await using NpgsqlDataReader prepareReader = await prepareCommand.ExecuteReaderAsync();
                AccountDeleteFinalizePreparationResult prepareResult = await ReadAccountDeleteFinalizePreparationResultAsync(prepareReader);
                await prepareReader.DisposeAsync();

                if (!prepareResult.Result)
                {
                    await tran.CommitAsync();
                    return new AccountDeleteCommandResult(false, prepareResult.Code, prepareResult.Workflow, null, prepareResult.AccountId);
                }

                bool passPhraseSatisfied = prepareResult.Workflow != DeletionWorkflow.PASS_PHRASE;
                if (prepareResult.Workflow == DeletionWorkflow.PASS_PHRASE)
                {
                    passPhraseSatisfied = !string.IsNullOrWhiteSpace(passPhrase)
                        && !string.IsNullOrWhiteSpace(prepareResult.PassPhraseHash)
                        && _userSecretHasher.VerifyUserSecret(passPhrase, prepareResult.PassPhraseHash);
                }

                await using NpgsqlCommand commitCommand = RepositoryCommands.CreateFunctionCommand(
                    CommitAccountDeleteFinalizeFunction,
                    conn,
                    tran,
                    "accountId",
                    "accountSecurityStamp",
                    "deleteTokenHash",
                    "passPhraseSatisfied",
                    "maxFailedFinalizeAttempts",
                    "finalizeLockout");

                commitCommand.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
                commitCommand.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
                commitCommand.Parameters.Add("@deleteTokenHash", NpgsqlDbType.Text).Value = deleteTokenHash;
                commitCommand.Parameters.Add("@passPhraseSatisfied", NpgsqlDbType.Boolean).Value = passPhraseSatisfied;
                commitCommand.Parameters.Add("@maxFailedFinalizeAttempts", NpgsqlDbType.Smallint).Value = maxFailedFinalizeAttempts;
                commitCommand.Parameters.Add("@finalizeLockout", NpgsqlDbType.Interval).Value = finalizeLockout;

                await using NpgsqlDataReader commitReader = await commitCommand.ExecuteReaderAsync();
                AccountDeleteCommandResult result = await ReadAccountDeleteFinalizeResultAsync(commitReader);
                await commitReader.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, $"{PrepareAccountDeleteFinalizeFunction}/{CommitAccountDeleteFinalizeFunction}", new { accountId });
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(FinalizeAccountDelete), new { accountId });
            return null;
        }
    }

    public async Task<AccountDeletePurgeResult?> PurgeExpiredDeleteStandby(Instant moment)
    {
        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                PurgeExpiredDeleteStandbyFunction,
                conn,
                tran,
                "moment");

            command.Parameters.Add("@moment", InstantDbType).Value = moment;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountDeletePurgeResult result = await ReadAccountDeletePurgeResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText);
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(PurgeExpiredDeleteStandby));
            return null;
        }
    }

    public async Task<AccountEmailChangePurgeResult?> PurgeExpiredAccountEmailChangeRequests(Instant moment)
    {
        try
        {
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                PurgeExpiredAccountEmailChangeRequestsFunction,
                conn,
                tran,
                "moment");

            command.Parameters.Add("@moment", InstantDbType).Value = moment;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountEmailChangePurgeResult result = await ReadAccountEmailChangePurgeResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText);
                return null;
            }
            finally
            {
                await conn.CloseAsync();
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(PurgeExpiredAccountEmailChangeRequests));
            return null;
        }
    }

    public async Task<AccountViewResult?> ViewAccount(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                ViewAccountFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                AccountViewResult result = await ReadAccountViewResultAsync(dr);
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
            LogRepositoryFailure(ex, nameof(ViewAccount), new { accountId });
            return null;
        }
    }

    public async Task<DbCommandResult?> PromoteTwoFactorNewLogin(
        Guid accountId,
        string expectedPreAuthAccessTokenHash,
        Guid accountSecurityStamp,
        string newAccessTokenHash,
        Session newSession)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            const string procedure = PromoteTwoFactorNewLoginFunction;
            string[] parameterNames =
            {
                "accountId",
                "expectedTwoFactorAccessToken",
                "accountSecurityStamp",
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
                "securityStamp"
            };

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, parameterNames);

            AddTwoFactorPromotionSessionParameters(command, accountId, expectedPreAuthAccessTokenHash, accountSecurityStamp, newAccessTokenHash, newSession);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                DbCommandResult result = await SessionRepo.ReadDbCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, procedure, RepositoryLogScopes.AccountTokenHash(accountId, newAccessTokenHash));
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(PromoteTwoFactorNewLogin), RepositoryLogScopes.AccountTokenHash(accountId, newAccessTokenHash));
            return null;
        }
    }

    public async Task<DbCommandResult?> PromoteTwoFactorRotationLogin(
        Guid accountId,
        string expectedPreAuthAccessTokenHash,
        Guid accountSecurityStamp,
        string expectedOldAccessTokenHash,
        string newAccessTokenHash,
        Session newSession)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            const string procedure = PromoteTwoFactorRotationLoginFunction;
            string[] parameterNames =
            {
                "accountId",
                "expectedTwoFactorAccessToken",
                "accountSecurityStamp",
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
                "securityStamp"
            };

            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(procedure, conn, tran, parameterNames);

            command.Parameters.Add("@expectedOldAccessTokenHash", SessionRepo.AccessTokenHashDbType).Value = expectedOldAccessTokenHash;
            AddTwoFactorPromotionSessionParameters(command, accountId, expectedPreAuthAccessTokenHash, accountSecurityStamp, newAccessTokenHash, newSession);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                DbCommandResult result = await SessionRepo.ReadDbCommandResultAsync(dr);
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
            LogRepositoryFailure(ex, nameof(PromoteTwoFactorRotationLogin), RepositoryLogScopes.AccountTokenHashes(accountId, expectedOldAccessTokenHash, newAccessTokenHash));
            return null;
        }
    }

    private void AddTwoFactorPromotionSessionParameters(
        NpgsqlCommand command,
        Guid accountId,
        string expectedPreAuthAccessTokenHash,
        Guid accountSecurityStamp,
        string newAccessTokenHash,
        Session newSession)
    {
        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
        command.Parameters.Add("@expectedTwoFactorAccessToken", NpgsqlDbType.Text).Value = expectedPreAuthAccessTokenHash;
        command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = AccountSecurityStampGuard.Require(accountSecurityStamp);
        command.Parameters.Add("@newAccessTokenHash", SessionRepo.AccessTokenHashDbType).Value = newAccessTokenHash;
        command.Parameters.Add("@refreshToken", RefreshTokenDbType).Value = newSession.refreshToken;
        command.Parameters.Add("@refreshes", NpgsqlDbType.Smallint).Value = DbValue(newSession.refreshes);
        command.Parameters.Add("@limit", NpgsqlDbType.Smallint).Value = DbValue(newSession.limit);
        command.Parameters.Add("@createdOn", InstantDbType).Value = newSession.createdOn;
        command.Parameters.Add("@sessionLifespan", NpgsqlDbType.Interval).Value = DbValue(newSession.sessionLifespan);
        command.Parameters.Add("@accessExpiration", InstantDbType).Value = newSession.accessExpiration;
        command.Parameters.Add("@sessionExpiration", InstantDbType).Value = newSession.sessionExpiration;
        command.Parameters.Add("@cutOff", InstantDbType).Value = DbValue(newSession.cutOff);
        command.Parameters.Add("@features", NpgsqlDbType.Smallint).Value = (short)newSession.features;
        command.Parameters.Add("@securityStamp", NpgsqlDbType.Uuid).Value = newSession.securityStamp;
    }


    internal static async Task<TwoFactorChallengeCommandResult> ReadTwoFactorChallengeCommandResultAsync(NpgsqlDataReader reader)
    {
        if (!await reader.ReadAsync())
        {
            return new TwoFactorChallengeCommandResult(false, "NO_RESULT", 0, 0, null, null);
        }

        bool result = reader.FieldCount > 0 && !reader.IsDBNull(0) && reader.GetBoolean(0);
        string code = reader.FieldCount > 1 && !reader.IsDBNull(1) ? reader.GetString(1) : "UNKNOWN";
        short attempts = reader.FieldCount > 2 && !reader.IsDBNull(2) ? reader.GetInt16(2) : (short)0;
        short resends = reader.FieldCount > 3 && !reader.IsDBNull(3) ? reader.GetInt16(3) : (short)0;
        Instant? challengeExpiration = reader.FieldCount > 4 && !reader.IsDBNull(4) ? reader.GetFieldValue<Instant>(4) : null;
        Instant? nextChallengeAllowedAt = reader.FieldCount > 5 && !reader.IsDBNull(5) ? reader.GetFieldValue<Instant>(5) : null;
        return new TwoFactorChallengeCommandResult(result, code, attempts, resends, challengeExpiration, nextChallengeAllowedAt);
    }

    internal static async Task<TwoFactorSetupCommandResult> ReadTwoFactorSetupCommandResultAsync(NpgsqlDataReader reader)
    {
        if (!await reader.ReadAsync())
        {
            return new TwoFactorSetupCommandResult(false, "NO_RESULT", null, null);
        }

        bool result = reader.GetBoolean(0);
        string code = reader.GetString(1);
        short? twoFactorIndex = reader.IsDBNull(2) ? null : reader.GetInt16(2);
        Instant? expiration = reader.IsDBNull(3) ? null : reader.GetFieldValue<Instant>(3);
        return new TwoFactorSetupCommandResult(result, code, twoFactorIndex, expiration);
    }

    public async Task<TwoFactorSetupCommandResult?> BeginTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        Instant createdOn,
        Instant expiration,
        string? emailAddress,
        string? phoneNumber,
        string? phoneCountryCode,
        string? authId,
        bool required)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                BeginTwoFactorSetupFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "tokenHash",
                "createdOn",
                "expiration",
                "emailAddress",
                "phoneNumber",
                "phoneCountryCode",
                "authId",
                "required");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;
            command.Parameters.Add("@emailAddress", NpgsqlDbType.Text).Value = DbValue(emailAddress);
            command.Parameters.Add("@phoneNumber", NpgsqlDbType.Text).Value = DbValue(phoneNumber);
            command.Parameters.Add("@phoneCountryCode", NpgsqlDbType.Text).Value = DbValue(phoneCountryCode);
            command.Parameters.Add("@authId", NpgsqlDbType.Text).Value = DbValue(authId);
            command.Parameters.Add("@required", NpgsqlDbType.Boolean).Value = required;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                TwoFactorSetupCommandResult result = await ReadTwoFactorSetupCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(BeginTwoFactorSetup), new { accountId, method });
            return null;
        }
    }

    public async Task<DbCommandResult?> CancelTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CancelTwoFactorSetupFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "tokenHash");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                DbCommandResult result = await SessionRepo.ReadDbCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CancelTwoFactorSetup), new { accountId, method });
            return null;
        }
    }

    internal static async Task<TwoFactorSetupVerificationCommandResult> ReadTwoFactorSetupVerificationCommandResultAsync(NpgsqlDataReader reader)
    {
        if (!await reader.ReadAsync())
        {
            return new TwoFactorSetupVerificationCommandResult(false, "NO_RESULT", 0, null);
        }

        bool result = reader.FieldCount > 0 && !reader.IsDBNull(0) && reader.GetBoolean(0);
        string code = reader.FieldCount > 1 && !reader.IsDBNull(1) ? reader.GetString(1) : "UNKNOWN";
        short attempts = reader.FieldCount > 2 && !reader.IsDBNull(2) ? reader.GetInt16(2) : (short)0;
        Instant? expiration = reader.FieldCount > 3 && !reader.IsDBNull(3) ? reader.GetFieldValue<Instant>(3) : null;
        return new TwoFactorSetupVerificationCommandResult(result, code, attempts, expiration);
    }

    public async Task<TwoFactorSetupVerificationCommandResult?> VerifyTwoFactorSetup(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        string tokenHash,
        short maxAttempts,
        Instant moment)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                VerifyTwoFactorSetupFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "tokenHash",
                "maxAttempts",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@tokenHash", NpgsqlDbType.Text).Value = tokenHash;
            command.Parameters.Add("@maxAttempts", NpgsqlDbType.Smallint).Value = maxAttempts;
            command.Parameters.Add("@now", InstantDbType).Value = moment;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                TwoFactorSetupVerificationCommandResult result = await ReadTwoFactorSetupVerificationCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(VerifyTwoFactorSetup), new { accountId, method });
            return null;
        }
    }

    internal static async Task<TwoFactorMethodRemovalCommandResult> ReadTwoFactorMethodRemovalCommandResultAsync(NpgsqlDataReader reader)
    {
        if (!await reader.ReadAsync())
        {
            return new TwoFactorMethodRemovalCommandResult(false, "NO_RESULT", TwoFactorAuthMethod.NONE, [], []);
        }

        bool result = reader.FieldCount > 0 && !reader.IsDBNull(0) && reader.GetBoolean(0);
        string code = reader.FieldCount > 1 && !reader.IsDBNull(1) ? reader.GetString(1) : "UNKNOWN";
        TwoFactorAuthMethod removedMethod = reader.FieldCount > 2 && !reader.IsDBNull(2)
            ? (TwoFactorAuthMethod)reader.GetInt16(2)
            : TwoFactorAuthMethod.NONE;
        List<TwoFactorAuthMethod> methods = ReadTwoFactorAuthMethods(reader, 3);
        List<TwoFactorAuthConfiguration> configurations = ReadTwoFactorAuthConfigurations(reader, 4);
        return new TwoFactorMethodRemovalCommandResult(result, code, removedMethod, methods, configurations);
    }

    public async Task<TwoFactorMethodRemovalCommandResult?> RemoveTwoFactorMethod(
        Guid accountId,
        Guid accountSecurityStamp,
        TwoFactorAuthMethod method,
        Instant moment)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RemoveTwoFactorMethodFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "method",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@method", NpgsqlDbType.Smallint).Value = (short)method;
            command.Parameters.Add("@now", InstantDbType).Value = moment;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                TwoFactorMethodRemovalCommandResult result = await ReadTwoFactorMethodRemovalCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, method });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RemoveTwoFactorMethod), new { accountId, method });
            return null;
        }
    }


    public async Task<bool?> BeginTwoFactorSession(
        Guid accountId,
        Guid accountSecurityStamp,
        short? twoAuthUsage,
        string preAuthAccessTokenHash,
        Instant createdOn,
        Instant expiration)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            bool? result = false;
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                BeginTwoFactorAuthDetailFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "twoFactorAccessToken",
                "twoAuthUsage",
                "createdOn",
                "expiration");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@twoFactorAccessToken", NpgsqlDbType.Text).Value = preAuthAccessTokenHash;
            command.Parameters.Add("@twoAuthUsage", NpgsqlDbType.Smallint).Value = DbValue(twoAuthUsage);
            command.Parameters.Add("@createdOn", InstantDbType).Value = createdOn;
            command.Parameters.Add("@expiration", InstantDbType).Value = expiration;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                result = await ReadBooleanProcedureResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(BeginTwoFactorSession), new { accountId });
            return null;
        }
    }

    public async Task<TwoFactorChallengeCommandResult?> RecordTwoFactorChallengeIssued(
        Guid accountId,
        Guid accountSecurityStamp,
        string expectedPreAuthAccessTokenHash,
        TwoFactorAuthMethod challengedMethod,
        short chosenDestination,
        string? challengeCodeHash,
        string? challengeProviderTransactionId,
        Instant challengeExpiration,
        Instant nextChallengeAllowedAt,
        short maxResends,
        Instant moment,
        TwoFactorAuthConfiguration? selectedConfiguration = null,
        TwoFactorSessionState? state = null,
        IReadOnlyCollection<TwoFactorAuthMethod>? requiredMethods = null,
        IReadOnlyCollection<TwoFactorAuthMethod>? completedMethods = null,
        TwoFactorAuthMethod? currentExpectedMethod = null,
        Instant? selectedAt = null)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RecordTwoFactorChallengeIssuedFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "expectedTwoFactorAccessToken",
                "challengedMethod",
                "chosenDestination",
                "challengeCodeHash",
                "challengeProviderTransactionId",
                "challengeExpiration",
                "nextChallengeAllowedAt",
                "maxResends",
                "now",
                "selectedTwoFactorConfiguration",
                "state",
                "requiredMethods",
                "completedMethods",
                "currentExpectedMethod",
                "selectedAt");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@expectedTwoFactorAccessToken", NpgsqlDbType.Text).Value = expectedPreAuthAccessTokenHash;
            command.Parameters.Add("@challengedMethod", NpgsqlDbType.Smallint).Value = (short)challengedMethod;
            command.Parameters.Add("@chosenDestination", NpgsqlDbType.Smallint).Value = chosenDestination;
            command.Parameters.Add("@challengeCodeHash", NpgsqlDbType.Text).Value = DbValue(challengeCodeHash);
            command.Parameters.Add("@challengeProviderTransactionId", NpgsqlDbType.Text).Value = DbValue(challengeProviderTransactionId);
            command.Parameters.Add("@challengeExpiration", InstantDbType).Value = challengeExpiration;
            command.Parameters.Add("@nextChallengeAllowedAt", InstantDbType).Value = nextChallengeAllowedAt;
            command.Parameters.Add("@maxResends", NpgsqlDbType.Smallint).Value = maxResends;
            command.Parameters.Add("@now", InstantDbType).Value = moment;
            command.Parameters.Add("@selectedTwoFactorConfiguration", NpgsqlDbType.Smallint).Value = DbValue(ToSmallint(selectedConfiguration));
            command.Parameters.Add("@state", NpgsqlDbType.Smallint).Value = DbValue(ToSmallint(state));
            command.Parameters.Add("@requiredMethods", NpgsqlDbType.Array | NpgsqlDbType.Smallint).Value = DbValue(ToSmallintArray(requiredMethods));
            command.Parameters.Add("@completedMethods", NpgsqlDbType.Array | NpgsqlDbType.Smallint).Value = DbValue(ToSmallintArray(completedMethods));
            command.Parameters.Add("@currentExpectedMethod", NpgsqlDbType.Smallint).Value = DbValue(ToSmallint(currentExpectedMethod));
            command.Parameters.Add("@selectedAt", InstantDbType).Value = DbValue(selectedAt);

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                TwoFactorChallengeCommandResult result = await ReadTwoFactorChallengeCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, challengedMethod });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RecordTwoFactorChallengeIssued), new { accountId, challengedMethod });
            return null;
        }
    }

    public async Task<TwoFactorChallengeCommandResult?> CancelTwoFactorChallengeIssued(
        Guid accountId,
        Guid accountSecurityStamp,
        string expectedPreAuthAccessTokenHash,
        TwoFactorAuthMethod challengedMethod,
        short chosenDestination,
        string? challengeCodeHash,
        string? challengeProviderTransactionId,
        Instant moment)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                CancelTwoFactorChallengeIssuedFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "expectedTwoFactorAccessToken",
                "challengedMethod",
                "chosenDestination",
                "challengeCodeHash",
                "challengeProviderTransactionId",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@expectedTwoFactorAccessToken", NpgsqlDbType.Text).Value = expectedPreAuthAccessTokenHash;
            command.Parameters.Add("@challengedMethod", NpgsqlDbType.Smallint).Value = (short)challengedMethod;
            command.Parameters.Add("@chosenDestination", NpgsqlDbType.Smallint).Value = chosenDestination;
            command.Parameters.Add("@challengeCodeHash", NpgsqlDbType.Text).Value = DbValue(challengeCodeHash);
            command.Parameters.Add("@challengeProviderTransactionId", NpgsqlDbType.Text).Value = DbValue(challengeProviderTransactionId);
            command.Parameters.Add("@now", InstantDbType).Value = moment;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                TwoFactorChallengeCommandResult result = await ReadTwoFactorChallengeCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId, challengedMethod });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(CancelTwoFactorChallengeIssued), new { accountId, challengedMethod });
            return null;
        }
    }

    public async Task<TwoFactorChallengeCommandResult?> RecordTwoFactorChallengeFailure(
        Guid accountId,
        Guid accountSecurityStamp,
        string expectedPreAuthAccessTokenHash,
        short maxAttempts,
        Instant moment)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            await using NpgsqlConnection conn = await _activeDatabase.CreateConnection();
            await using NpgsqlTransaction tran = await conn.BeginTransactionAsync();
            await using NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(
                RecordTwoFactorChallengeFailureFunction,
                conn,
                tran,
                "accountId",
                "accountSecurityStamp",
                "expectedTwoFactorAccessToken",
                "maxAttempts",
                "now");

            command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
            command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
            command.Parameters.Add("@expectedTwoFactorAccessToken", NpgsqlDbType.Text).Value = expectedPreAuthAccessTokenHash;
            command.Parameters.Add("@maxAttempts", NpgsqlDbType.Smallint).Value = maxAttempts;
            command.Parameters.Add("@now", InstantDbType).Value = moment;

            try
            {
                await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                TwoFactorChallengeCommandResult result = await ReadTwoFactorChallengeCommandResultAsync(dr);
                await dr.DisposeAsync();
                await tran.CommitAsync();
                return result;
            }
            catch (Exception ex)
            {
                await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId });
                return null;
            }
        }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RecordTwoFactorChallengeFailure), new { accountId });
            return null;
        }
    }

    //set login failures to zero and clear out twoFactorAccessToken
    //maybe clear out any pending password reset or account recoveries?
    public async Task<bool?> SuccessfulTwoFactorAuth(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("successful_twofactor_auth", conn, tran, "accountId", "expectedTwoFactorAccessToken", "accountSecurityStamp"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
                        command.Parameters.Add("@expectedTwoFactorAccessToken", NpgsqlDbType.Text).Value = expectedPreAuthAccessTokenHash;
                        command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(SuccessfulTwoFactorAuth));
            return null;
        }
    }

    public async Task<bool?> IsPendingTwoFactorSessionCurrent(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("is_pending_twofactor_session_current", conn, tran, "accountId", "expectedTwoFactorAccessToken", "accountSecurityStamp"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
                        command.Parameters.Add("@expectedTwoFactorAccessToken", NpgsqlDbType.Text).Value = expectedPreAuthAccessTokenHash;
                        command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(IsPendingTwoFactorSessionCurrent));
            return null;
        }
    }

    //Set login failures to zero
    //maybe clear out any pending password reset or account recoveries?
    public async Task<bool?> SuccessfulLogin(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("successful_login", conn, tran, "accountId", "accountSecurityStamp"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
                        command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(SuccessfulLogin));
            return null;
        }
    }

    public async Task<bool?> RotateAccountSecurityStamp(Guid accountId)
    {
        try
        {
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand(RotateAccountSecurityStampProcedure, conn, tran, "accountId"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText, new { accountId });
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }

            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(RotateAccountSecurityStamp));
            return null;
        }
    }

    public async Task<bool?> Set2FASession(Guid accountId, Guid accountSecurityStamp, short? twoAuthUsage, string preAuthAccessTokenHash)
    {
        try
        {
            AccountSecurityStampGuard.Require(accountSecurityStamp);
            bool? result = false;
            await using (NpgsqlConnection conn = await _activeDatabase.CreateConnection())
            {
                await using (NpgsqlTransaction tran = await conn.BeginTransactionAsync())
                {
                    await using (NpgsqlCommand command = RepositoryCommands.CreateFunctionCommand("set_twofactor_auth_detail", conn, tran, "accountId", "accountSecurityStamp", "twoFactorAccessToken", "twoAuthUsage"))
                    {
                        command.Parameters.Add("@accountId", NpgsqlDbType.Uuid).Value = accountId;
                        command.Parameters.Add("@accountSecurityStamp", NpgsqlDbType.Uuid).Value = accountSecurityStamp;
                        command.Parameters.Add("@twoFactorAccessToken", NpgsqlDbType.Text).Value = preAuthAccessTokenHash;
                        command.Parameters.Add("@twoAuthUsage", NpgsqlDbType.Smallint).Value = DbValue(twoAuthUsage);

                        try
                        {
                            await using NpgsqlDataReader dr = await command.ExecuteReaderAsync();
                            result = await ReadBooleanProcedureResultAsync(dr);
                            await dr.DisposeAsync();
                            await tran.CommitAsync();
                        }
                        catch (Exception ex)
                        {
                            await RollbackAndLogAsync(tran, ex, command.CommandText);
                            result = null;
                        }
                        finally
                        {
                            await conn.CloseAsync();
                        }
                    }
                }
            }
            return result;
            }
        catch (Exception ex)
        {
            LogRepositoryFailure(ex, nameof(Set2FASession));
            return null;
        }
    }


    internal static async Task<AccountAdjustResult> ReadAccountAdjustResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountAdjustResult(false, "NO_RESULT");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Guid? accountSecurityStamp = null;
        string? emailAddress = null;

        for (int index = 2; index < dr.FieldCount; index++)
        {
            if (dr.IsDBNull(index))
            {
                continue;
            }

            string columnName = dr.GetName(index);
            if (columnName.Equals("account_security_stamp", StringComparison.OrdinalIgnoreCase))
            {
                accountSecurityStamp = dr.GetGuid(index);
                continue;
            }

            if (columnName.Equals("email_address", StringComparison.OrdinalIgnoreCase))
            {
                emailAddress = dr.GetString(index);
            }
        }

        return new AccountAdjustResult(result, code, accountSecurityStamp, emailAddress);
    }

    internal static async Task<AccountDeleteCommandResult> ReadAccountDeleteRequestResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountDeleteCommandResult(false, "NO_RESULT");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        string? emailAddress = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetString(2) : null;
        DeletionWorkflow workflow = dr.FieldCount > 3 && !dr.IsDBNull(3)
            ? (DeletionWorkflow)dr.GetInt16(3)
            : DeletionWorkflow.NONE;

        return new AccountDeleteCommandResult(result, code, workflow, emailAddress);
    }

    internal static async Task<AccountDeleteCommandResult> ReadAccountDeleteVerifyResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountDeleteCommandResult(false, "NO_RESULT");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        DeletionWorkflow workflow = dr.FieldCount > 2 && !dr.IsDBNull(2)
            ? (DeletionWorkflow)dr.GetInt16(2)
            : DeletionWorkflow.NONE;

        return new AccountDeleteCommandResult(result, code, workflow);
    }

    internal static async Task<AccountDeleteFinalizePreparationResult> ReadAccountDeleteFinalizePreparationResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountDeleteFinalizePreparationResult(false, "NO_RESULT", null, DeletionWorkflow.NONE, null);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Guid? accountId = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetGuid(2) : null;
        DeletionWorkflow workflow = dr.FieldCount > 3 && !dr.IsDBNull(3)
            ? (DeletionWorkflow)dr.GetInt16(3)
            : DeletionWorkflow.NONE;
        string? passPhraseHash = dr.FieldCount > 4 && !dr.IsDBNull(4) ? dr.GetString(4) : null;

        return new AccountDeleteFinalizePreparationResult(result, code, accountId, workflow, passPhraseHash);
    }

    internal static async Task<AccountDeleteCommandResult> ReadAccountDeleteFinalizeResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountDeleteCommandResult(false, "NO_RESULT");
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        Guid? accountId = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetGuid(2) : null;
        return new AccountDeleteCommandResult(result, code, DeletionWorkflow.NONE, null, accountId);
    }

    internal static async Task<AccountDeletePurgeResult> ReadAccountDeletePurgeResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountDeletePurgeResult(false, "NO_RESULT", 0);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        int deletedCount = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetInt32(2) : 0;
        return new AccountDeletePurgeResult(result, code, deletedCount);
    }

    internal static async Task<AccountEmailChangePurgeResult> ReadAccountEmailChangePurgeResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountEmailChangePurgeResult(false, "NO_RESULT", 0);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";
        int deletedCount = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetInt32(2) : 0;
        return new AccountEmailChangePurgeResult(result, code, deletedCount);
    }

    internal static async Task<AccountViewResult> ReadAccountViewResultAsync(NpgsqlDataReader dr)
    {
        if (!await dr.ReadAsync())
        {
            return new AccountViewResult(false, "NO_RESULT", null);
        }

        bool result = dr.FieldCount > 0 && !dr.IsDBNull(0) && dr.GetBoolean(0);
        string code = dr.FieldCount > 1 && !dr.IsDBNull(1) ? dr.GetString(1) : "UNKNOWN";

        if (!result)
        {
            return new AccountViewResult(false, code, null);
        }

        List<TwoFactorAuthMethod> twoFactorAuthMethods = ReadTwoFactorAuthMethods(dr, 10);
        TwoFactorAuthConfiguration twoFactorAuthConfiguration = dr.FieldCount > 9 && !dr.IsDBNull(9)
            ? (TwoFactorAuthConfiguration)dr.GetInt16(9)
            : TwoFactorAuthConfigurationResolver.FromMethods(twoFactorAuthMethods);

        var profile = new AccountProfile
        {
            emailAddress = dr.FieldCount > 2 && !dr.IsDBNull(2) ? dr.GetString(2) : string.Empty,
            username = dr.FieldCount > 3 && !dr.IsDBNull(3) ? dr.GetString(3) : null,
            createdOn = dr.FieldCount > 4 && !dr.IsDBNull(4) ? dr.GetFieldValue<Instant>(4) : Instant.MinValue,
            verifyStatus = dr.FieldCount > 5 && !dr.IsDBNull(5) ? (VerificationStatus)dr.GetInt16(5) : VerificationStatus.FAILED,
            country = dr.FieldCount > 6 && !dr.IsDBNull(6) ? (Country)dr.GetInt16(6) : Country.NONE,
            features = dr.FieldCount > 7 && !dr.IsDBNull(7) ? (FeatureSet)dr.GetInt16(7) : FeatureSet.basic,
            twoFactorEnabled = dr.FieldCount > 8 && !dr.IsDBNull(8) && dr.GetBoolean(8),
            twoFactorAuthConfiguration = twoFactorAuthConfiguration,
            twoFactorAuthMethods = twoFactorAuthMethods,
            availableTwoFactorAuthConfigurations = TwoFactorAuthConfigurationResolver.AvailableFromMethods(twoFactorAuthMethods)
        };

        return new AccountViewResult(true, code, profile);
    }

    internal static List<TwoFactorAuthMethod> ReadTwoFactorAuthMethods(NpgsqlDataReader dr, int ordinal)
    {
        if (dr.FieldCount <= ordinal || dr.IsDBNull(ordinal))
        {
            return [];
        }

        short[] rawMethods;
        try
        {
            rawMethods = dr.GetFieldValue<short[]>(ordinal);
        }
        catch (InvalidCastException)
        {
            return [];
        }

        return rawMethods
            .Where(value => Enum.IsDefined(typeof(TwoFactorAuthMethod), (int)value))
            .Select(value => (TwoFactorAuthMethod)value)
            .Where(method => method is not TwoFactorAuthMethod.NONE)
            .Distinct()
            .ToList();
    }

    internal static List<TwoFactorAuthConfiguration> ReadTwoFactorAuthConfigurations(NpgsqlDataReader dr, int ordinal)
    {
        if (dr.FieldCount <= ordinal || dr.IsDBNull(ordinal))
        {
            return [];
        }

        short[] rawConfigurations;
        try
        {
            rawConfigurations = dr.GetFieldValue<short[]>(ordinal);
        }
        catch (InvalidCastException)
        {
            return [];
        }

        return rawConfigurations
            .Where(value => Enum.IsDefined(typeof(TwoFactorAuthConfiguration), (int)value))
            .Select(value => (TwoFactorAuthConfiguration)value)
            .Where(configuration => configuration is not TwoFactorAuthConfiguration.NONE and not TwoFactorAuthConfiguration.CUSTOM)
            .Distinct()
            .ToList();
    }


    internal static async Task<bool> ReadBooleanProcedureResultAsync(NpgsqlDataReader reader, int ordinal = 0)
    {
        bool hasRow = await reader.ReadAsync();
        if (!hasRow)
        {
            return false;
        }

        return ReadBooleanResult(reader, ordinal);
    }

    internal static bool ReadBooleanResult(NpgsqlDataReader reader, int ordinal = 0)
    {
        object value = reader.GetValue(ordinal);
        return ReadBooleanValue(value);
    }

    internal static bool ReadBooleanValue(object? value)
    {
        return value switch
        {
            null => false,
            DBNull _ => false,
            bool boolValue => boolValue,
            short shortValue => shortValue > 0,
            int intValue => intValue > 0,
            long longValue => longValue > 0,
            _ => Convert.ToBoolean(value)
        };
    }

    internal static bool ReadBooleanContractResult(bool hasRow, object? value)
    {
        return hasRow && ReadBooleanValue(value);
    }


    internal static object DbValue(object? value)
    {
        return value ?? DBNull.Value;
    }

    internal static short? ToSmallint<TEnum>(TEnum? value) where TEnum : struct, Enum
    {
        return value.HasValue ? Convert.ToInt16(value.Value) : null;
    }

    internal static short[]? ToSmallintArray(IEnumerable<TwoFactorAuthMethod>? methods)
    {
        if (methods is null)
        {
            return null;
        }

        return methods.Select(method => Convert.ToInt16(method)).ToArray();
    }


    private void LogRepositoryFailure(Exception exception, string operation, object? scope = null)
    {
        _logger.LogError(exception, "Repository operation {Operation} failed before a controlled repository result could be returned with scope {@Scope}.", operation, scope);
    }

    private async Task RollbackAndLogAsync(NpgsqlTransaction tran, Exception exception, string? procedure, object? scope = null)
    {
        try
        {
            await tran.RollbackAsync();
        }
        catch (Exception rollbackException)
        {
            _logger.LogError(rollbackException, "Rollback failed for repository procedure {Procedure}.", procedure ?? "<unset>");
        }

        _logger.LogError(exception, "Repository procedure {Procedure} failed with scope {@Scope}.", procedure ?? "<unset>", scope);
    }
}
