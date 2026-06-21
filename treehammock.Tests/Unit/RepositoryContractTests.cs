using System.Reflection;
using NpgsqlTypes;
using Shouldly;

using treehammock.Repos;
using treehammock.Services;
using treehammock.Models.Account;
using treehammock.RiggingSupport.Enum;

namespace treehammock.Tests.Unit;

public class RepositoryContractTests
{
    [Fact]
    public void Account_anonymous_verification_models_bound_token_payload_lengths()
    {
        AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength.ShouldBe(512);
        AccountDeleteVerifyRequest.MaxDeleteTokenLength.ShouldBe(512);
    }

    [Fact]
    public void Repositories_do_not_contain_rollback_then_commit_sequences()
    {
        foreach (string path in RepositorySourceFiles())
        {
            string source = File.ReadAllText(path);
            source.ShouldNotContain("RollbackAsync();\r\n                        await tran.CommitAsync();");
            source.ShouldNotContain("RollbackAsync();\n                        await tran.CommitAsync();");
        }
    }

    [Fact]
    public void AccountRepo_get_credentials_disposes_reader_before_committing_transaction()
    {
        string source = File.ReadAllText(Path.Combine(ProjectRoot(), "Repos", "AccountRepo.cs"));
        int methodStart = source.IndexOf("public async Task<CredentialLookupResult> GetCredentials", StringComparison.Ordinal);
        methodStart.ShouldBeGreaterThanOrEqualTo(0);
        int methodEnd = source.IndexOf("public Period FindLockoutPeriod", methodStart, StringComparison.Ordinal);
        methodEnd.ShouldBeGreaterThan(methodStart);
        string method = source[methodStart..methodEnd];

        int readerStart = method.IndexOf("await using (NpgsqlDataReader dr = await command.ExecuteReaderAsync())", StringComparison.Ordinal);
        int commit = method.IndexOf("await tran.CommitAsync();", StringComparison.Ordinal);
        int resultReturn = method.IndexOf("return result;", StringComparison.Ordinal);

        readerStart.ShouldBeGreaterThanOrEqualTo(0);
        commit.ShouldBeGreaterThan(readerStart);
        resultReturn.ShouldBeGreaterThan(commit);
        method.ShouldContain("result = CredentialLookupResult.Found(mapped);");
        method.ShouldContain("result = CredentialLookupResult.NotFound();");
        method.ShouldNotContain("await tran.CommitAsync();" + Environment.NewLine + "                    return CredentialLookupResult.Found");
        method.ShouldNotContain("await tran.CommitAsync();" + Environment.NewLine + "                return CredentialLookupResult.NotFound");
    }

    [Fact]
    public void SessionRepo_uses_expected_parameter_types()
    {
        SessionRepo.AccessTokenHashDbType.ShouldBe(NpgsqlDbType.Text);
        SessionRepo.RefreshTokenDbType.ShouldBe(NpgsqlDbType.Bytea);
        SessionRepo.InstantDbType.ShouldBe(NpgsqlDbType.TimestampTz);
        SessionRepo.FeatureSetDbType.ShouldBe(NpgsqlDbType.Smallint);
    }

    [Fact]
    public void SessionRepo_persists_session_metadata_needed_for_cache_rehydration_without_configurable_concurrency_modes()
    {
        string source = File.ReadAllText(Path.Combine(ProjectRoot(), "Repos", "SessionRepo.cs"));
        source.ShouldContain("@cutOff");
        source.ShouldContain("@features");
        source.ShouldNotContain("@sessionConcurrencyMode");
    }

    [Fact]
    public void Baseline_sql_enforces_single_session_per_account_without_session_mode_switches()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        baseline.ShouldNotContain("p_sessionConcurrencyMode");
        baseline.ShouldNotContain("many_sessions_per_account");
        baseline.ShouldNotContain("device_scoped_sessions");
        baseline.ShouldContain("where account_id = p_accountId");
        baseline.ShouldContain("and session_expiration > now();");
    }

    [Fact]
    public void AccountRepo_uses_timestamp_tz_for_instant_parameters()
    {
        AccountRepo.InstantDbType.ShouldBe(NpgsqlDbType.TimestampTz);
    }

    [Fact]
    public void ActivationRepo_uses_timestamp_tz_for_instant_parameters()
    {
        ActivationRepo.InstantDbType.ShouldBe(NpgsqlDbType.TimestampTz);
    }

    [Fact]
    public void AccountRecoveryRepo_uses_guid_account_id_and_lockout_snapshot_for_unlock_contract()
    {
        MethodInfo method = typeof(IAccountRecoveryRepo).GetMethod(nameof(IAccountRecoveryRepo.BeginUnlock))!;
        ParameterInfo[] parameters = method.GetParameters();

        parameters[0].ParameterType.ShouldBe(typeof(Guid));
        parameters.Any(parameter => parameter.Name == "deliveryMethod" && parameter.ParameterType == typeof(AccountUnlockDeliveryMethod)).ShouldBeTrue();
        parameters.Any(parameter => parameter.Name == "accountSecurityStamp" && parameter.ParameterType == typeof(Guid)).ShouldBeTrue();
        parameters.Any(parameter => parameter.Name == "lockoutUnlockWhen" && parameter.ParameterType == typeof(NodaTime.Instant)).ShouldBeTrue();
        AccountRecoveryRepo.InstantDbType.ShouldBe(NpgsqlDbType.TimestampTz);
    }

    [Fact]
    public void Nullable_parameter_values_are_converted_to_DBNull()
    {
        SessionRepo.DbValue(null).ShouldBe(DBNull.Value);
        ActivationRepo.DbValue(null).ShouldBe(DBNull.Value);
        AccountRepo.DbValue(null).ShouldBe(DBNull.Value);
        PasswordResetRepo.DbValue(null).ShouldBe(DBNull.Value);

        SessionRepo.DbValue("value").ShouldBe("value");
        ActivationRepo.DbValue("value").ShouldBe("value");
        AccountRepo.DbValue("value").ShouldBe("value");
        PasswordResetRepo.DbValue("value").ShouldBe("value");
    }

    [Fact]
    public void ActivationRepo_reads_explicit_activation_result_code_contracts()
    {
        string source = File.ReadAllText(Path.Combine(ProjectRoot(), "Repos", "ActivationRepo.cs"));

        source.ShouldContain("ActivationCommandResult");
        source.ShouldContain("ActivationVerifyCommandResult");
        source.ShouldContain("dr.GetBoolean(0)");
        source.ShouldContain("dr.GetString(1)");
        source.ShouldNotContain("return activations;");
        source.ShouldNotContain("ReadActivationStatusAsync");
    }


    [Fact]
    public void Repositories_do_not_use_stored_procedure_command_type_for_application_contracts()
    {
        foreach (string path in RepositorySourceFiles())
        {
            string source = File.ReadAllText(path);
            source.ShouldNotContain("CommandType.StoredProcedure");
        }
    }


    [Fact]
    public void Runtime_sources_do_not_use_the_old_authentication_namespace_typo()
    {
        foreach (string path in Directory.EnumerateFiles(ProjectRoot(), "*.cs", SearchOption.AllDirectories))
        {
            if (path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}") ||
                path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            {
                continue;
            }

            string source = File.ReadAllText(path);
            source.ShouldNotContain("Authe" + "tication");
        }
    }

    [Fact]
    public void Account_service_interface_exposes_registration_and_email_change_contracts()
    {
        string[] methodNames = typeof(IAccountService)
            .GetMethods()
            .Select(method => method.Name)
            .OrderBy(name => name)
            .ToArray();

        methodNames.ShouldBe(new[]
        {
            nameof(IAccountService.CompleteEmailChange),
            nameof(IAccountService.FinalizeAccountDelete),
            nameof(IAccountService.PurgeExpiredAccountEmailChangeRequests),
            nameof(IAccountService.PurgeExpiredDeleteStandby),
            nameof(IAccountService.RequestAccountDelete),
            nameof(IAccountService.RequestEmailChange),
            nameof(IAccountService.ResendAccountVerification),
            nameof(IAccountService.SetupUserAccount),
            nameof(IAccountService.VerifyAccountDeleteToken)
        });
    }

    [Fact]
    public void Session_expiration_path_does_not_hard_delete_runtime_sessions()
    {
        string sessionRepo = File.ReadAllText(Path.Combine(ProjectRoot(), "Repos", "SessionRepo.cs"));
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sessionRepo.ShouldNotContain("RevokeSessionProcedure");
        sessionRepo.ShouldContain("A null value means \"expire now\"");
        baseline.ShouldContain("Legacy compatibility wrapper. Runtime repository code uses expire_session");
        baseline.ShouldNotContain("delete from sessions\n     where access_token_hash = p_accessTokenHash");
    }


    [Fact]
    public void Two_factor_challenge_counters_are_durable_in_greenfield_baseline()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        baseline.ShouldContain("create table if not exists pending_two_factor_sessions");
        baseline.ShouldContain("selected_two_factor_configuration smallint null");
        baseline.ShouldContain("state smallint not null default 1");
        baseline.ShouldContain("available_configurations smallint[] not null default array[]::smallint[]");
        baseline.ShouldContain("required_methods smallint[] not null default array[]::smallint[]");
        baseline.ShouldContain("completed_methods smallint[] not null default array[]::smallint[]");
        baseline.ShouldContain("current_expected_method smallint null");
        baseline.ShouldContain("selected_at timestamp with time zone null");
        baseline.ShouldContain("completed_at timestamp with time zone null");
        baseline.ShouldContain("challenge_attempts smallint not null default 0");
        baseline.ShouldContain("challenge_resends smallint not null default 0");
        baseline.ShouldContain("resolve_available_twofactor_configurations");
        baseline.ShouldContain("state = 1");
        baseline.ShouldContain("record_twofactor_challenge_issued");
        baseline.ShouldContain("record_twofactor_challenge_failure");
        baseline.ShouldContain("delete from pending_two_factor_sessions");
    }


    [Fact]
    public void Account_view_and_delete_models_do_not_reintroduce_client_owned_account_identity()
    {
        string accountDetails = File.ReadAllText(Path.Combine(ProjectRoot(), "Models", "Account", "AccountDetails.cs"));
        string accountDelete = File.ReadAllText(Path.Combine(ProjectRoot(), "Models", "Account", "AccountDelete.cs"));
        string modelsDirectory = Path.Combine(ProjectRoot(), "Models", "Account");

        accountDetails.ShouldNotContain("AccountDetailsRequest");
        accountDetails.ShouldNotContain("public required string emailAddress { get; set; }");
        accountDelete.ShouldNotContain("AccountDeletePassphraseRequest");
        accountDelete.ShouldNotContain("emailAddress");
        accountDelete.ShouldNotContain("currentTime");

        string accountRecovery = File.ReadAllText(Path.Combine(ProjectRoot(), "Models", "Recovery", "AccountRecovery.cs"));
        accountRecovery.ShouldNotContain("currentTime");
        accountRecovery.ShouldNotContain("LocalDateTime");

        File.Exists(Path.Combine(modelsDirectory, "AccountStatus.cs")).ShouldBeFalse();
        File.Exists(Path.Combine(ProjectRoot(), "Entities", "AccountRecovery.cs")).ShouldBeFalse();
    }

    [Fact]
    public void Recovery_and_delete_secrets_are_stored_as_hashes_in_greenfield_baseline()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        baseline.ShouldContain("token_hash text not null");
        baseline.ShouldContain("pass_phrase_hash text null");
        baseline.ShouldContain("delete_token_hash text not null unique");
        baseline.ShouldContain("create table if not exists account_email_change_requests");
        baseline.ShouldContain("verify_key_hash text not null unique");
        baseline.ShouldNotContain("token text not null");
        baseline.ShouldNotContain("pass_phrase text null");
        baseline.ShouldNotContain("delete_token text unique null");
        baseline.ShouldNotContain("delete_token text not null unique");
        baseline.ShouldNotContain("where token =");
        baseline.ShouldNotContain("where delete_token =");
        baseline.ShouldNotContain("and pass_phrase =");

        int deleteStandbyStart = baseline.IndexOf("create table if not exists delete_standby(", StringComparison.Ordinal);
        deleteStandbyStart.ShouldBeGreaterThanOrEqualTo(0);
        int deleteStandbyEnd = baseline.IndexOf("create table if not exists account_delete_events", deleteStandbyStart, StringComparison.Ordinal);
        deleteStandbyEnd.ShouldBeGreaterThan(deleteStandbyStart);
        string deleteStandbyTable = baseline[deleteStandbyStart..deleteStandbyEnd];
        deleteStandbyTable.ShouldContain("delete_token_hash text not null unique");
        deleteStandbyTable.ShouldContain("pass_phrase_hash text null");
        deleteStandbyTable.ShouldNotContain("delete_token text");
        deleteStandbyTable.ShouldNotContain("pass_phrase text");
        deleteStandbyTable.ShouldNotContain("verify_key_hash");

        int auditTableStart = baseline.IndexOf("create table if not exists account_delete_events(", StringComparison.Ordinal);
        auditTableStart.ShouldBeGreaterThanOrEqualTo(0);
        int auditTableEnd = baseline.IndexOf("create table if not exists session_logout_events", auditTableStart, StringComparison.Ordinal);
        auditTableEnd.ShouldBeGreaterThan(auditTableStart);
        string auditTable = baseline[auditTableStart..auditTableEnd];
        auditTable.ShouldContain("account_id uuid null");
        auditTable.ShouldContain("event_type text not null");
        auditTable.ShouldContain("code text not null");
        auditTable.ShouldContain("created_at timestamp with time zone not null default now()");
        auditTable.ShouldNotContain("delete_token");
        auditTable.ShouldNotContain("pass_phrase");
        auditTable.ShouldNotContain("verify_key_hash");
    }

    [Fact]
    public void Recovery_repository_hashes_raw_tokens_and_account_operation_repositories_accept_hash_contracts()
    {
        string accountRepo = File.ReadAllText(Path.Combine(ProjectRoot(), "Repos", "AccountRepo.cs"));
        string recoveryRepo = File.ReadAllText(Path.Combine(ProjectRoot(), "Repos", "AccountRecoveryRepo.cs"));

        recoveryRepo.ShouldContain("SecretHashUtility.HashToken(token)");
        recoveryRepo.ShouldContain("tokenHash");
        accountRepo.ShouldContain("string deleteTokenHash");
        accountRepo.ShouldContain("string? passPhraseHash");
        accountRepo.ShouldContain("string? passPhrase,");
        accountRepo.ShouldContain("string verifyKeyHash");
        accountRepo.ShouldNotContain("SecretHashUtility.HashToken(deleteToken)");
        accountRepo.ShouldNotContain("SecretHashUtility.HashOptionalToken(passPhrase)");
        accountRepo.ShouldContain("_userSecretHasher.VerifyUserSecret(passPhrase, prepareResult.PassPhraseHash)");
        accountRepo.ShouldNotContain("SecretHashUtility.HashToken(single.deleteToken)");
        accountRepo.ShouldNotContain("SecretHashUtility.HashToken(single.passPhrase)");
    }

    [Fact]
    public void Repository_function_names_are_present_in_greenfield_baseline_sql()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        string[] expectedFunctions =
        {
            "setup_account_email",
            "setup_account_both",
            "start_verify_account",
            "resend_verify_account",
            "verify_account_for_use",
            "complete_verify_account",
            "expire_verify_account",
            "check_account_emailaddress_creds",
            "check_account_username_creds",
            "check_account_both_creds",
            "get_account_reauthentication_credentials",
            "issue_sensitive_action_token",
            "validate_sensitive_action_token",
            "get_current_active_session_hash",
            "set_account_lockout",
            "remove_account_lockout",
            "set_account_login_failures",
            "successful_login",
            "rotate_account_security_stamp",
            "set_twofactor_auth_detail",
            "begin_twofactor_auth_detail",
            "begin_twofactor_setup",
            "cancel_twofactor_setup",
            "verify_twofactor_setup",
            "record_twofactor_challenge_issued",
            "cancel_twofactor_challenge_issued",
            "record_twofactor_challenge_failure",
            "is_pending_twofactor_session_current",
            "successful_twofactor_auth",
            "promote_twofactor_new_login",
            "promote_twofactor_rotation_login",
            "edit_account_username",
            "request_account_email_change",
            "cancel_account_email_change_request",
            "complete_account_email_change",
            "purge_expired_account_email_change_requests",
            "request_account_delete",
            "cancel_account_delete_request",
            "verify_account_delete_token",
            "prepare_account_delete_finalize",
            "commit_account_delete_finalize",
            "purge_expired_delete_standby",
            "get_twofactor_details",
            "view_account",
            "lookup_locked_recovery_account",
            "start_unlock_account",
            "cancel_unlock_account",
            "verify_unlock_account",
            "place_activation",
            "cancel_activation_request",
            "verify_activation",
            "disable_activation",
            "get_session",
            "set_session",
            "rotate_active_session",
            "validate_cached_session_trust",
            "expire_session",
            "revoke_session",
            "update_refresh_token",
            "logout_current_session",
            "logout_all_sessions",
            "list_active_sessions",
            "revoke_session_for_account"
        };

        foreach (string functionName in expectedFunctions)
        {
            baseline.ShouldContain($"create or replace function {functionName}");
        }
    }


    [Fact]
    public void Account_operation_sql_contracts_use_authenticated_context_and_safe_profile_shape()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        baseline.ShouldContain("create or replace function view_account(\n    p_accountId uuid,\n    p_accountSecurityStamp uuid)");
        baseline.ShouldContain("create or replace function edit_account_username(\n    p_accountId uuid,\n    p_accountSecurityStamp uuid,\n    p_username text)");
        baseline.ShouldContain("create or replace function prepare_account_delete_finalize(\n    p_accountId uuid,\n    p_accountSecurityStamp uuid,");
        baseline.ShouldContain("create or replace function commit_account_delete_finalize(\n    p_accountId uuid,");
        baseline.ShouldContain("create or replace function cancel_account_email_change_request(");
        baseline.ShouldContain("create or replace function purge_expired_account_email_change_requests(");
        baseline.ShouldContain("create or replace function cancel_account_delete_request(");
        baseline.ShouldContain("create or replace function purge_expired_delete_standby(");
        baseline.ShouldContain("ACCOUNT_ADJUST_PURGE_SUCCEEDED");
        baseline.ShouldContain("ACCOUNT_ADJUST_PURGE_FAILED");
        baseline.ShouldContain("ACCOUNT_DELETE_RATE_LIMITED");
        baseline.ShouldContain("ACCOUNT_DELETE_ATTEMPT_LIMITED");
        baseline.ShouldContain("ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED");
        baseline.ShouldContain("ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED");
        baseline.ShouldContain("two_factor_enabled boolean");
        baseline.ShouldContain("'ACCOUNT_VIEW_SUCCEEDED'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_SUCCEEDED'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_DUPLICATE_USERNAME'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_DUPLICATE_EMAIL'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_EMAIL_CHANGE_CANCELLED'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_TOKEN_EXPIRED'::text");
        baseline.ShouldContain("'ACCOUNT_ADJUST_TOKEN_MISMATCH'::text");
        baseline.ShouldContain("'ACCOUNT_NOT_FOUND'::text");
        baseline.ShouldContain("'ACCOUNT_SECURITY_STAMP_MISMATCH'::text");
        baseline.ShouldNotContain("create or replace function edit_account_emailAddress");
        baseline.ShouldNotContain("create or replace function edit_account_username(p_username text)");
        baseline.ShouldNotContain("create or replace function delete_account(");
        baseline.ShouldNotContain("create or replace function passphrase_delete_account");
        baseline.ShouldNotContain("create or replace function verify_delete_account");

        int viewStart = baseline.IndexOf("create or replace function view_account(", StringComparison.Ordinal);
        viewStart.ShouldBeGreaterThanOrEqualTo(0);
        int viewEnd = baseline.IndexOf("create or replace function start_unlock_account", viewStart, StringComparison.Ordinal);
        viewEnd.ShouldBeGreaterThan(viewStart);
        string viewFunction = baseline[viewStart..viewEnd];
        viewFunction.ShouldContain("'ACCOUNT_VIEW_SUCCEEDED'::text");
        viewFunction.ShouldContain("'ACCOUNT_NOT_FOUND'::text");
        viewFunction.ShouldContain("'ACCOUNT_SECURITY_STAMP_MISMATCH'::text");
        viewFunction.ShouldNotContain("ACCOUNT_VIEW_NOT_IMPLEMENTED");
        viewFunction.ShouldNotContain("hashed_password");
        viewFunction.ShouldNotContain("web_key");

        int editUsernameStart = baseline.IndexOf("create or replace function edit_account_username(", StringComparison.Ordinal);
        editUsernameStart.ShouldBeGreaterThanOrEqualTo(0);
        int editUsernameEnd = baseline.IndexOf("create or replace function request_account_email_change", editUsernameStart, StringComparison.Ordinal);
        editUsernameEnd.ShouldBeGreaterThan(editUsernameStart);
        string editUsernameFunction = baseline[editUsernameStart..editUsernameEnd];
        editUsernameFunction.ShouldContain("where account_id = p_accountId");
        editUsernameFunction.ShouldContain("account_record.security_stamp <> p_accountSecurityStamp");
        editUsernameFunction.ShouldContain("lower(username) = lower(normalized_username)");
        editUsernameFunction.ShouldContain("'ACCOUNT_ADJUST_SUCCEEDED'::text");
        editUsernameFunction.ShouldContain("'ACCOUNT_ADJUST_DUPLICATE_USERNAME'::text");
        editUsernameFunction.ShouldNotContain("ACCOUNT_ADJUST_NOT_IMPLEMENTED");

        int requestEmailStart = baseline.IndexOf("create or replace function request_account_email_change(", StringComparison.Ordinal);
        requestEmailStart.ShouldBeGreaterThanOrEqualTo(0);
        int requestEmailEnd = baseline.IndexOf("create or replace function cancel_account_email_change_request", requestEmailStart, StringComparison.Ordinal);
        requestEmailEnd.ShouldBeGreaterThan(requestEmailStart);
        string requestEmailFunction = baseline[requestEmailStart..requestEmailEnd];
        requestEmailFunction.ShouldContain("where a.account_id = p_accountId");
        requestEmailFunction.ShouldContain("account_record.security_stamp <> p_accountSecurityStamp");
        requestEmailFunction.ShouldContain("verify_key_hash");
        requestEmailFunction.ShouldContain("ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING");
        requestEmailFunction.ShouldContain("ACCOUNT_ADJUST_DUPLICATE_EMAIL");
        requestEmailFunction.ShouldContain("p_expiration is null or p_expiration <= now()");
        requestEmailFunction.ShouldNotContain("ACCOUNT_ADJUST_NOT_IMPLEMENTED");

        int cancelEmailStart = baseline.IndexOf("create or replace function cancel_account_email_change_request(", StringComparison.Ordinal);
        cancelEmailStart.ShouldBeGreaterThanOrEqualTo(0);
        int cancelEmailEnd = baseline.IndexOf("create or replace function complete_account_email_change", cancelEmailStart, StringComparison.Ordinal);
        cancelEmailEnd.ShouldBeGreaterThan(cancelEmailStart);
        string cancelEmailFunction = baseline[cancelEmailStart..cancelEmailEnd];
        cancelEmailFunction.ShouldContain("account_record.security_stamp <> p_accountSecurityStamp");
        cancelEmailFunction.ShouldContain("where account_id = p_accountId");
        cancelEmailFunction.ShouldContain("verify_key_hash = p_verifyKeyHash");
        cancelEmailFunction.ShouldContain("delete from account_email_change_requests");
        cancelEmailFunction.ShouldContain("ACCOUNT_ADJUST_EMAIL_CHANGE_CANCELLED");
        cancelEmailFunction.ShouldContain("ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED");

        int completeEmailStart = baseline.IndexOf("create or replace function complete_account_email_change(", StringComparison.Ordinal);
        completeEmailStart.ShouldBeGreaterThanOrEqualTo(0);
        int completeEmailEnd = baseline.IndexOf("create or replace function request_account_delete", completeEmailStart, StringComparison.Ordinal);
        completeEmailEnd.ShouldBeGreaterThan(completeEmailStart);
        string completeEmailFunction = baseline[completeEmailStart..completeEmailEnd];
        completeEmailFunction.ShouldContain("where verify_key_hash = p_verifyKeyHash");
        completeEmailFunction.ShouldContain("security_stamp = new_security_stamp");
        completeEmailFunction.ShouldContain("update sessions");
        completeEmailFunction.ShouldContain("delete from account_email_change_requests");
        completeEmailFunction.ShouldContain("ACCOUNT_ADJUST_SUCCEEDED");
        completeEmailFunction.ShouldContain("ACCOUNT_ADJUST_TOKEN_EXPIRED");
        completeEmailFunction.ShouldNotContain("ACCOUNT_ADJUST_NOT_IMPLEMENTED");

        int purgeEmailStart = baseline.IndexOf("create or replace function purge_expired_account_email_change_requests(", StringComparison.Ordinal);
        purgeEmailStart.ShouldBeGreaterThanOrEqualTo(0);
        int purgeEmailEnd = baseline.IndexOf("create or replace function request_account_delete", purgeEmailStart, StringComparison.Ordinal);
        purgeEmailEnd.ShouldBeGreaterThan(purgeEmailStart);
        string purgeEmailFunction = baseline[purgeEmailStart..purgeEmailEnd];
        purgeEmailFunction.ShouldContain("delete from account_email_change_requests");
        purgeEmailFunction.ShouldContain("where expiration <= p_now");
        purgeEmailFunction.ShouldContain("ACCOUNT_ADJUST_PURGE_SUCCEEDED");

        int requestDeleteStart = baseline.IndexOf("create or replace function request_account_delete(", StringComparison.Ordinal);
        requestDeleteStart.ShouldBeGreaterThanOrEqualTo(0);
        int requestDeleteEnd = baseline.IndexOf("create or replace function prepare_account_delete_finalize", requestDeleteStart, StringComparison.Ordinal);
        requestDeleteEnd.ShouldBeGreaterThan(requestDeleteStart);
        string requestDeleteFunction = baseline[requestDeleteStart..requestDeleteEnd];
        requestDeleteFunction.ShouldContain("where account_id = p_accountId");
        requestDeleteFunction.ShouldContain("account_record.security_stamp <> p_accountSecurityStamp");
        requestDeleteFunction.ShouldContain("delete_token_hash");
        requestDeleteFunction.ShouldContain("ACCOUNT_DELETE_PENDING");
        requestDeleteFunction.ShouldContain("insert into account_delete_events(account_id, event_type, code)");
        requestDeleteFunction.ShouldContain("'REQUESTED'");
        requestDeleteFunction.ShouldContain("ACCOUNT_DELETE_RATE_LIMITED");
        requestDeleteFunction.ShouldContain("'REQUEST_RATE_LIMITED'");
        requestDeleteFunction.ShouldContain("p_expiration is null or p_expiration <= now()");
        requestDeleteFunction.ShouldContain("next_request_allowed_at > now()");
        requestDeleteFunction.ShouldContain("requested_count >= p_maxRequestsPerWindow");
        requestDeleteFunction.ShouldContain("existing_delete.expiration > now()");
        requestDeleteFunction.ShouldContain("now() + p_requestCooldown");
        requestDeleteFunction.ShouldContain("now() - p_requestWindow");
        requestDeleteFunction.ShouldContain("ACCOUNT_NOT_FOUND");
        requestDeleteFunction.ShouldContain("ACCOUNT_SECURITY_STAMP_MISMATCH");
        requestDeleteFunction.ShouldNotContain("ACCOUNT_DELETE_NOT_IMPLEMENTED");
        requestDeleteFunction.ShouldNotContain("verify_key_hash");
        requestDeleteFunction.ShouldNotContain("interval '15 minutes'");
        requestDeleteFunction.ShouldNotContain("interval '1 day'");
        requestDeleteFunction.ShouldNotContain("max_requests_per_window");

        int cancelDeleteStart = baseline.IndexOf("create or replace function cancel_account_delete_request(", StringComparison.Ordinal);
        cancelDeleteStart.ShouldBeGreaterThanOrEqualTo(0);
        int cancelDeleteEnd = baseline.IndexOf("create or replace function prepare_account_delete_finalize", cancelDeleteStart, StringComparison.Ordinal);
        cancelDeleteEnd.ShouldBeGreaterThan(cancelDeleteStart);
        string cancelDeleteFunction = baseline[cancelDeleteStart..cancelDeleteEnd];
        cancelDeleteFunction.ShouldContain("where account_id = p_accountId");
        cancelDeleteFunction.ShouldContain("and delete_token_hash = p_deleteTokenHash");
        cancelDeleteFunction.ShouldContain("account_record.security_stamp <> p_accountSecurityStamp");
        cancelDeleteFunction.ShouldContain("delete from delete_standby");
        cancelDeleteFunction.ShouldContain("ACCOUNT_DELETE_REQUEST_CANCELLED");
        cancelDeleteFunction.ShouldContain("ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED");
        cancelDeleteFunction.ShouldContain("ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED");
        cancelDeleteFunction.ShouldContain("'REQUEST_CANCELLED'");

        int prepareDeleteStart = baseline.IndexOf("create or replace function prepare_account_delete_finalize(", StringComparison.Ordinal);
        prepareDeleteStart.ShouldBeGreaterThanOrEqualTo(0);
        int prepareDeleteEnd = baseline.IndexOf("create or replace function commit_account_delete_finalize", prepareDeleteStart, StringComparison.Ordinal);
        prepareDeleteEnd.ShouldBeGreaterThan(prepareDeleteStart);
        string prepareDeleteFunction = baseline[prepareDeleteStart..prepareDeleteEnd];
        prepareDeleteFunction.ShouldContain("where a.account_id = p_accountId");
        prepareDeleteFunction.ShouldContain("account_record.security_stamp <> p_accountSecurityStamp");
        prepareDeleteFunction.ShouldContain("and d.delete_token_hash = p_deleteTokenHash");
        prepareDeleteFunction.ShouldContain("delete_record.verified is distinct from true");
        prepareDeleteFunction.ShouldContain("pass_phrase_hash text");
        prepareDeleteFunction.ShouldContain("p_maxFailedFinalizeAttempts smallint");
        prepareDeleteFunction.ShouldContain("p_finalizeLockout interval");
        prepareDeleteFunction.ShouldContain("'FINALIZE_LOCKED'");
        prepareDeleteFunction.ShouldNotContain("p_passPhraseHash");
        prepareDeleteFunction.ShouldNotContain("ACCOUNT_DELETE_NOT_IMPLEMENTED");

        int commitDeleteStart = baseline.IndexOf("create or replace function commit_account_delete_finalize(", StringComparison.Ordinal);
        commitDeleteStart.ShouldBeGreaterThanOrEqualTo(0);
        int commitDeleteEnd = baseline.IndexOf("create or replace function rotate_active_session", commitDeleteStart, StringComparison.Ordinal);
        commitDeleteEnd.ShouldBeGreaterThan(commitDeleteStart);
        string commitDeleteFunction = baseline[commitDeleteStart..commitDeleteEnd];
        commitDeleteFunction.ShouldContain("p_accountSecurityStamp uuid");
        commitDeleteFunction.ShouldContain("p_passPhraseSatisfied boolean");
        commitDeleteFunction.ShouldContain("p_maxFailedFinalizeAttempts smallint");
        commitDeleteFunction.ShouldContain("p_finalizeLockout interval");
        commitDeleteFunction.ShouldContain("account_record.security_stamp <> p_accountSecurityStamp");
        commitDeleteFunction.ShouldContain("failed_finalize_attempts = next_failed_attempts");
        commitDeleteFunction.ShouldContain("finalize_locked_until = case");
        commitDeleteFunction.ShouldContain("now() + p_finalizeLockout");
        commitDeleteFunction.ShouldContain("p_maxFailedFinalizeAttempts");
        commitDeleteFunction.ShouldContain("ACCOUNT_DELETE_ATTEMPT_LIMITED");
        commitDeleteFunction.ShouldContain("ACCOUNT_DELETE_VERIFY_REQUIRED");
        commitDeleteFunction.ShouldContain("ACCOUNT_DELETE_SUCCEEDED");
        commitDeleteFunction.ShouldContain("'FINALIZE_FAILED'");
        commitDeleteFunction.ShouldContain("'FINALIZE_LOCKED'");
        commitDeleteFunction.ShouldContain("'COMPLETED'");
        commitDeleteFunction.ShouldContain("insert into account_delete_events(account_id, event_type, code)");
        commitDeleteFunction.ShouldContain("delete from accounts");
        commitDeleteFunction.ShouldNotContain("p_passPhraseHash");
        commitDeleteFunction.ShouldNotContain("ACCOUNT_DELETE_NOT_IMPLEMENTED");
        commitDeleteFunction.ShouldNotContain("interval '30 minutes'");
        commitDeleteFunction.ShouldNotContain("max_failed_finalize_attempts");

        int verifyDeleteStart = baseline.IndexOf("create or replace function verify_account_delete_token(", StringComparison.Ordinal);
        verifyDeleteStart.ShouldBeGreaterThanOrEqualTo(0);
        int verifyDeleteEnd = baseline.IndexOf("create or replace function view_account", verifyDeleteStart, StringComparison.Ordinal);
        verifyDeleteEnd.ShouldBeGreaterThan(verifyDeleteStart);
        string verifyDeleteFunction = baseline[verifyDeleteStart..verifyDeleteEnd];
        verifyDeleteFunction.ShouldContain("where delete_token_hash = p_deleteTokenHash");
        verifyDeleteFunction.ShouldContain("for update");
        verifyDeleteFunction.ShouldContain("set verified = true");
        verifyDeleteFunction.ShouldContain("ACCOUNT_DELETE_VERIFIED");
        verifyDeleteFunction.ShouldContain("'VERIFIED'");
        verifyDeleteFunction.ShouldContain("'VERIFY_FAILED'");
        verifyDeleteFunction.ShouldContain("ACCOUNT_DELETE_TOKEN_EXPIRED");
        verifyDeleteFunction.ShouldNotContain("ACCOUNT_DELETE_NOT_IMPLEMENTED");

        int purgeDeleteStart = baseline.IndexOf("create or replace function purge_expired_delete_standby(", StringComparison.Ordinal);
        purgeDeleteStart.ShouldBeGreaterThanOrEqualTo(0);
        int purgeDeleteEnd = baseline.IndexOf("create or replace function view_account", purgeDeleteStart, StringComparison.Ordinal);
        purgeDeleteEnd.ShouldBeGreaterThan(purgeDeleteStart);
        string purgeDeleteFunction = baseline[purgeDeleteStart..purgeDeleteEnd];
        purgeDeleteFunction.ShouldContain("delete from delete_standby");
        purgeDeleteFunction.ShouldContain("where expiration <= p_now");
        purgeDeleteFunction.ShouldContain("ACCOUNT_DELETE_PURGE_SUCCEEDED");
        purgeDeleteFunction.ShouldContain("insert into account_delete_events(account_id, event_type, code)");
        purgeDeleteFunction.ShouldContain("'PURGED'");

        int deleteStandbyStart = baseline.IndexOf("create table if not exists delete_standby(", StringComparison.Ordinal);
        deleteStandbyStart.ShouldBeGreaterThanOrEqualTo(0);
        int deleteStandbyEnd = baseline.IndexOf("create table if not exists account_delete_events", deleteStandbyStart, StringComparison.Ordinal);
        deleteStandbyEnd.ShouldBeGreaterThan(deleteStandbyStart);
        string deleteStandbyTable = baseline[deleteStandbyStart..deleteStandbyEnd];
        deleteStandbyTable.ShouldContain("delete_token_hash text not null unique");
        deleteStandbyTable.ShouldContain("pass_phrase_hash text null");
        deleteStandbyTable.ShouldContain("expiration timestamp with time zone not null");
        deleteStandbyTable.ShouldContain("requested_count smallint not null default 0");
        deleteStandbyTable.ShouldContain("last_requested_at timestamp with time zone null");
        deleteStandbyTable.ShouldContain("next_request_allowed_at timestamp with time zone null");
        deleteStandbyTable.ShouldContain("failed_finalize_attempts smallint not null default 0");
        deleteStandbyTable.ShouldContain("finalize_locked_until timestamp with time zone null");
        deleteStandbyTable.ShouldNotContain("delete_token text");
        deleteStandbyTable.ShouldNotContain("pass_phrase text");
        deleteStandbyTable.ShouldNotContain("verify_key_hash");

        int auditTableStart = baseline.IndexOf("create table if not exists account_delete_events(", StringComparison.Ordinal);
        auditTableStart.ShouldBeGreaterThanOrEqualTo(0);
        int auditTableEnd = baseline.IndexOf("create table if not exists session_logout_events", auditTableStart, StringComparison.Ordinal);
        auditTableEnd.ShouldBeGreaterThan(auditTableStart);
        string auditTable = baseline[auditTableStart..auditTableEnd];
        auditTable.ShouldContain("account_id uuid null");
        auditTable.ShouldContain("event_type text not null");
        auditTable.ShouldContain("code text not null");
        auditTable.ShouldContain("created_at timestamp with time zone not null default now()");
        auditTable.ShouldContain("ix_account_delete_events_account_time");
        auditTable.ShouldNotContain("delete_token");
        auditTable.ShouldNotContain("pass_phrase");
        auditTable.ShouldNotContain("verify_key_hash");
    }


    [Fact]
    public void Session_logout_sql_contracts_distinguish_stale_stamp_from_missing_session_and_audit_every_branch()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        int logoutCurrentStart = baseline.IndexOf("create or replace function logout_current_session(", StringComparison.Ordinal);
        logoutCurrentStart.ShouldBeGreaterThanOrEqualTo(0);
        int logoutCurrentEnd = baseline.IndexOf("create or replace function logout_all_sessions", logoutCurrentStart, StringComparison.Ordinal);
        logoutCurrentEnd.ShouldBeGreaterThan(logoutCurrentStart);
        string logoutCurrentFunction = baseline[logoutCurrentStart..logoutCurrentEnd];
        logoutCurrentFunction.ShouldContain("a.security_stamp = p_accountSecurityStamp");
        logoutCurrentFunction.ShouldContain("return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text");
        logoutCurrentFunction.ShouldContain("return query select true, 'SESSION_ALREADY_MISSING_OR_STALE'::text");
        logoutCurrentFunction.ShouldContain("return query select true, 'CURRENT_SESSION_LOGGED_OUT'::text");
        logoutCurrentFunction.ShouldContain("insert into session_logout_events");
        logoutCurrentFunction.ShouldContain("completed,");
        logoutCurrentFunction.ShouldContain("false,");

        int logoutAllStart = baseline.IndexOf("create or replace function logout_all_sessions(", StringComparison.Ordinal);
        logoutAllStart.ShouldBeGreaterThanOrEqualTo(0);
        int logoutAllEnd = baseline.IndexOf("create or replace function list_active_sessions", logoutAllStart, StringComparison.Ordinal);
        logoutAllEnd.ShouldBeGreaterThan(logoutAllStart);
        string logoutAllFunction = baseline[logoutAllStart..logoutAllEnd];
        logoutAllFunction.ShouldContain("set security_stamp = newStamp");
        logoutAllFunction.ShouldContain("return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text, null::uuid");
        logoutAllFunction.ShouldContain("insert into session_logout_events");
        logoutAllFunction.ShouldContain("'ALL_SESSIONS_LOGGED_OUT'");

        int revokeStart = baseline.IndexOf("create or replace function revoke_session_for_account(", StringComparison.Ordinal);
        revokeStart.ShouldBeGreaterThanOrEqualTo(0);
        int revokeEnd = baseline.IndexOf("create or replace function get_twofactor_details", revokeStart, StringComparison.Ordinal);
        revokeEnd.ShouldBeGreaterThan(revokeStart);
        string revokeFunction = baseline[revokeStart..revokeEnd];
        revokeFunction.ShouldContain("return query select false, 'ACCOUNT_SECURITY_STAMP_MISMATCH'::text");
        revokeFunction.ShouldContain("return query select true, 'SESSION_ALREADY_MISSING_OR_STALE'::text");
        revokeFunction.ShouldContain("return query select true,");
        revokeFunction.ShouldContain("'CURRENT_SESSION_REVOKED'::text");
        revokeFunction.ShouldContain("'SESSION_REVOKED'::text");
        revokeFunction.ShouldContain("insert into session_logout_events");
    }


    [Fact]
    public void System_flow_sql_functions_qualify_columns_that_share_return_names()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        baseline.ShouldContain("set request_count = prrl.request_count + 1");
        baseline.ShouldContain("challenge_resends = case when p_challengedMethod = 3 then ptfs.challenge_resends else ptfs.challenge_resends + 1 end");
        baseline.ShouldContain("and sat.expiration > p_createdOn");
        baseline.ShouldContain("from accounts a\n     where a.account_id = p_accountId");
        baseline.ShouldContain("from delete_standby d\n     where d.account_id = p_accountId");
        baseline.ShouldContain("from account_recoveries ar\n     where ar.token_hash = p_tokenHash");
        baseline.ShouldContain("and ar.status in (1, 2, 3, 6)");
        baseline.ShouldContain("delete from accounts a\n     where a.account_id = p_accountId");
        baseline.ShouldContain("update two_factor_authentications tfa set verified = true");
        baseline.ShouldContain("tfa.two_factor_index = setup_record.two_factor_index");
    }

    [Fact]
    public void Session_expiration_revocation_sql_preserves_created_on_ordering()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        baseline.ShouldContain("greatest(created_on, now())");
        baseline.ShouldContain("greatest(s.created_on, now())");
        baseline.ShouldContain("greatest(created_on, moment)");
        baseline.ShouldNotContain("session_expiration = least(session_expiration, now())");
        baseline.ShouldNotContain("session_expiration = least(s.session_expiration, now())");
        baseline.ShouldNotContain("session_expiration = least(session_expiration, moment)");
    }

    [Fact]
    public void Authenticator_app_login_challenge_sql_does_not_consume_delivery_resend_cooldown()
    {
        string baseline = File.ReadAllText(Path.Combine(ProjectRoot(), "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        baseline.ShouldContain("if p_challengedMethod <> 3 and pending.next_challenge_allowed_at is not null and pending.next_challenge_allowed_at > p_now then");
        baseline.ShouldContain("if p_challengedMethod <> 3 and pending.challenge_resends >= p_maxResends then");
        baseline.ShouldContain("challenge_resends = case when p_challengedMethod = 3 then ptfs.challenge_resends else ptfs.challenge_resends + 1 end");
        baseline.ShouldContain("next_challenge_allowed_at = case when p_challengedMethod = 3 then ptfs.next_challenge_allowed_at else p_nextChallengeAllowedAt end");
    }

    [Fact]
    public void System_test_sms_sender_is_purpose_aware_for_setup_and_login_capture()
    {
        string source = File.ReadAllText(Path.Combine(ProjectRoot(), "Services", "SystemTesting", "SystemTestSmsSender.cs"));
        string systemTests = File.ReadAllText(Path.Combine(ProjectRoot(), "treehammock.Tests.System", "SystemStackAccountFlowTests.cs"));

        source.ShouldContain("SystemTestSmsSender : ISmsSender, ISystemTestPurposeAwareSmsSender");
        source.ShouldContain("Task<bool> SendCode(string phoneNumber, string codeKey, string purpose)");
        source.ShouldContain("NormalizeTestPhoneNumber");
        source.ShouldContain("$\"+1{trimmed}\"");
        systemTests.ShouldContain("private static string UniqueSmsPhone()");
        systemTests.ShouldContain("SmsPhone = UniqueSmsPhone();");
        systemTests.ShouldContain("SmsDestination = $\"+1{SmsPhone}\";");
    }

    private static IEnumerable<string> RepositorySourceFiles()
    {
        string root = ProjectRoot();
        yield return Path.Combine(root, "Repos", "AccountRepo.cs");
        yield return Path.Combine(root, "Repos", "SessionRepo.cs");
        yield return Path.Combine(root, "Repos", "ActivationRepo.cs");
        yield return Path.Combine(root, "Repos", "AccountRecoveryRepo.cs");
        yield return Path.Combine(root, "Repos", "SensitiveActionTokenRepo.cs");
    }

    private static string ProjectRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.csproj")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull();
        return directory.FullName;
    }
}
