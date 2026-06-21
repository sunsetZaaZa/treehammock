using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.PasswordReset;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class PasswordResetRepositorySqlIntegrationTests
{
    private const string ResetCode = "49382710";
    private const string ValidTotpCode = "123456";

    [Fact]
    public async Task PasswordResetRepo_promotes_password_and_invalidates_existing_sessions_against_real_sql()
    {
        string connectionString = RequiredConnectionString();
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "password_reset_repo_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await CreateSchemaAndLoadBaseline(setupConnection, schema);

            Guid accountId = Guid.NewGuid();
            byte[] oldHashedPassword = RepeatedByte(1, 128);
            byte[] oldSaltOne = RepeatedByte(2, 64);
            byte[] oldSiv = RepeatedByte(3, 32);
            byte[] oldNonce = RepeatedByte(4, 16);

            await ExecuteAsync(
                setupConnection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'repo-reset-reader@example.com', 'repo-reset-reader', @hashedPassword, 'repo-reset-web-key', @saltOne, @siv, @nonce,
                    3, 1, 1, 0);
                """,
                ("accountId", accountId),
                ("hashedPassword", oldHashedPassword),
                ("saltOne", oldSaltOne),
                ("siv", oldSiv),
                ("nonce", oldNonce));

            Guid accountSecurityStamp = await QueryGuidAsync(
                setupConnection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            await using var storage = new SearchPathStorageContext(connectionString, schema);
            var passwordResetRepo = new PasswordResetRepo(storage, NullLogger<PasswordResetRepo>.Instance);
            var sessionRepo = new SessionRepo(
                storage,
                Options.Create(new JWTSettings { RefreshTokenBytes = 64 }),
                NullLogger<SessionRepo>.Instance);

            Instant now = SystemClock.Instance.GetCurrentInstant();
            string accessTokenHash = "repo-password-reset-session";
            var session = new Session(
                accountId,
                RepeatedByte(5, 64),
                refreshes: 0,
                limit: 5,
                createdOn: now,
                sessionLifespan: Period.FromDays(7),
                accessExpiration: now.Plus(Duration.FromMinutes(10)),
                sessionExpiration: now.Plus(Duration.FromHours(1)),
                cutOff: null,
                features: FeatureSet.basic,
                securityStamp: Guid.NewGuid(),
                accountSecurityStamp: accountSecurityStamp);

            IntraMessage? sessionCreated = await sessionRepo.SetSession(accessTokenHash, session);
            sessionCreated.ShouldBe(IntraMessage.SUCCESSFUL);
            (await sessionRepo.GetSession(accessTokenHash)).ShouldNotBeNull();

            PasswordResetAccountLookupResult? lookup = await passwordResetRepo.LookupPasswordResetAccountAsync(
                "repo-reset-reader@example.com",
                now,
                CancellationToken.None);

            lookup.ShouldNotBeNull();
            lookup.Result.ShouldBeTrue();
            lookup.Code.ShouldBe("PASSWORD_RESET_ACCOUNT_FOUND");
            lookup.AccountId.ShouldBe(accountId);
            lookup.EmailVerified.ShouldBeTrue();
            lookup.AccountSecurityStamp.ShouldBe(accountSecurityStamp);

            Guid resetId = Guid.NewGuid();
            Instant expiresAt = now.Plus(Duration.FromMinutes(10));
            CreatePasswordResetRequestDbResult? created = await passwordResetRepo.CreatePasswordResetRequestAsync(
                new CreatePasswordResetRequestDbCommand(
                    resetId,
                    accountId,
                    "email",
                    "email",
                    "repo-reset-code-hash",
                    1,
                    "repo-destination-fingerprint",
                    "r***r@example.com",
                    true,
                    false,
                    expiresAt,
                    5,
                    "127.0.0.1",
                    "repository-sql-integration-test",
                    accountSecurityStamp),
                CancellationToken.None);

            created.ShouldNotBeNull();
            created.Result.ShouldBeTrue();
            created.Code.ShouldBe("PASSWORD_RESET_REQUEST_CREATED");
            created.PasswordResetRequestId.ShouldBe(resetId);
            created.AccountId.ShouldBe(accountId);
            created.ExpiresAt.ShouldNotBeNull();
            created.ExpiresAt.Value.ToUnixTimeSeconds().ShouldBe(expiresAt.ToUnixTimeSeconds());

            PasswordResetFinalizeRecord? finalizeRecord = await passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(resetId, CancellationToken.None);
            finalizeRecord.ShouldNotBeNull();
            finalizeRecord.Result.ShouldBeTrue();
            finalizeRecord.Code.ShouldBe("PASSWORD_RESET_READY");
            finalizeRecord.PasswordResetRequestId.ShouldBe(resetId);
            finalizeRecord.AccountId.ShouldBe(accountId);
            finalizeRecord.KeyCodeHash.ShouldBe("repo-reset-code-hash");
            finalizeRecord.RequiresKeyCode.ShouldBe(true);
            finalizeRecord.RequiresTotp.ShouldBe(false);

            byte[] newHashedPassword = RepeatedByte(9, 128);
            byte[] newSaltOne = RepeatedByte(8, 64);
            byte[] newSiv = RepeatedByte(7, 32);
            byte[] newNonce = RepeatedByte(6, 16);
            Guid newSecurityStamp = Guid.NewGuid();
            Instant promotedAt = now.Plus(Duration.FromSeconds(5));

            PromotePasswordResetResult? promoted = await passwordResetRepo.PromotePasswordResetAsync(
                new PromotePasswordResetDbCommand(
                    resetId,
                    accountId,
                    newHashedPassword,
                    newSaltOne,
                    newSiv,
                    newNonce,
                    newSecurityStamp,
                    promotedAt),
                CancellationToken.None);

            promoted.ShouldNotBeNull();
            promoted.Result.ShouldBeTrue();
            promoted.Code.ShouldBe("PASSWORD_RESET_COMPLETED");
            promoted.AccountId.ShouldBe(accountId);
            promoted.AccountSecurityStamp.ShouldBe(newSecurityStamp);
            promoted.ConsumedAt.ShouldNotBeNull();
            promoted.ConsumedAt.Value.ToUnixTimeSeconds().ShouldBe(promotedAt.ToUnixTimeSeconds());

            (await QueryGuidAsync(setupConnection, "select security_stamp from accounts where account_id = @accountId;", ("accountId", accountId))).ShouldBe(newSecurityStamp);
            (await QueryBytesAsync(setupConnection, "select hashed_password from accounts where account_id = @accountId;", ("accountId", accountId))).ShouldBe(newHashedPassword);
            (await QueryIntAsync(setupConnection, "select login_failures from accounts where account_id = @accountId;", ("accountId", accountId))).ShouldBe(0);
            (await QueryIntAsync(setupConnection, "select count(*) from sessions where access_token_hash = @accessTokenHash and cut_off is not null;", ("accessTokenHash", accessTokenHash))).ShouldBe(1);
            (await QueryIntAsync(setupConnection, "select count(*) from accounts where account_id = @accountId and cut_off is null;", ("accountId", accountId))).ShouldBe(1);
            (await QueryIntAsync(setupConnection, "select count(*) from password_reset_events where password_reset_request_id = @resetId and event_type = 'password_reset_completed';", ("resetId", resetId))).ShouldBe(1);
            (await sessionRepo.GetSession(accessTokenHash)).ShouldBeNull("password reset promotion must invalidate the old session through the account security-stamp/session trust model.");
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }

    [Fact]
    public async Task PasswordResetTotpRepo_loads_verified_authenticator_secret_and_rejects_replay_against_real_sql()
    {
        string connectionString = RequiredConnectionString();
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "password_reset_totp_repo_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await CreateSchemaAndLoadBaseline(setupConnection, schema);

            Guid accountId = Guid.NewGuid();
            await ExecuteAsync(
                setupConnection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'repo-totp-reader@example.com', 'repo-totp-reader', @hashedPassword, 'repo-totp-web-key', @saltOne, @siv, @nonce,
                    0, 1, 1, 3);

                insert into two_factor_authentications(
                    two_factor_index, account_id, method, verified, priority, required,
                    totp_secret_ciphertext, totp_secret_nonce, totp_secret_tag, totp_secret_version)
                values(
                    4, @accountId, 3, true, 0, true,
                    @ciphertext, @nonceBytes, @tag, 1);
                """,
                ("accountId", accountId),
                ("hashedPassword", RepeatedByte(1, 128)),
                ("saltOne", RepeatedByte(2, 64)),
                ("siv", RepeatedByte(3, 32)),
                ("nonce", RepeatedByte(4, 16)),
                ("ciphertext", new byte[] { 0xAA, 0x01, 0x02 }),
                ("nonceBytes", new byte[] { 0xBB, 0x03, 0x04 }),
                ("tag", new byte[] { 0xCC, 0x05, 0x06 }));

            await using var storage = new SearchPathStorageContext(connectionString, schema);
            var totpRepo = new PasswordResetTotpRepo(storage, NullLogger<PasswordResetTotpRepo>.Instance);

            PasswordResetTotpEnrollmentRecord? enrollment = await totpRepo.GetPasswordResetTotpEnrollmentAsync(
                accountId,
                SystemClock.Instance.GetCurrentInstant(),
                CancellationToken.None);

            enrollment.ShouldNotBeNull();
            enrollment.AccountId.ShouldBe(accountId);
            enrollment.TwoFactorIndex.ShouldBe((short)4);
            enrollment.Method.ShouldBe((short)3);
            enrollment.TotpSecretCiphertext.ShouldBe(new byte[] { 0xAA, 0x01, 0x02 });
            enrollment.TotpSecretNonce.ShouldBe(new byte[] { 0xBB, 0x03, 0x04 });
            enrollment.TotpSecretTag.ShouldBe(new byte[] { 0xCC, 0x05, 0x06 });
            enrollment.TotpSecretVersion.ShouldBe(1);
            enrollment.TotpLastUsedStep.ShouldBeNull();

            PasswordResetTotpStepResult? accepted = await totpRepo.MarkPasswordResetTotpStepUsedAsync(
                accountId,
                4,
                12_345,
                CancellationToken.None);
            accepted.ShouldNotBeNull();
            accepted.Result.ShouldBeTrue();
            accepted.Code.ShouldBe("TOTP_STEP_ACCEPTED");

            PasswordResetTotpStepResult? replay = await totpRepo.MarkPasswordResetTotpStepUsedAsync(
                accountId,
                4,
                12_345,
                CancellationToken.None);
            replay.ShouldNotBeNull();
            replay.Result.ShouldBeFalse();
            replay.Code.ShouldBe("TOTP_REPLAY_DETECTED");
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }


    [Fact]
    public async Task PasswordResetRepo_creating_second_active_reset_cancels_first_against_real_sql()
    {
        string connectionString = RequiredConnectionString();
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "password_reset_replace_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await CreateSchemaAndLoadBaseline(setupConnection, schema);

            Guid accountId = Guid.NewGuid();
            await ExecuteAsync(
                setupConnection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'repo-reset-replace@example.com', 'repo-reset-replace', @hashedPassword, 'repo-replace-web-key', @saltOne, @siv, @nonce,
                    0, 1, 1, 0);
                """,
                ("accountId", accountId),
                ("hashedPassword", RepeatedByte(1, 128)),
                ("saltOne", RepeatedByte(2, 64)),
                ("siv", RepeatedByte(3, 32)),
                ("nonce", RepeatedByte(4, 16)));

            Guid accountSecurityStamp = await QueryGuidAsync(
                setupConnection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            await using var storage = new SearchPathStorageContext(connectionString, schema);
            var passwordResetRepo = new PasswordResetRepo(storage, NullLogger<PasswordResetRepo>.Instance);

            Instant now = Instant.FromUnixTimeSeconds(1_900_000_000);
            Guid firstResetId = Guid.NewGuid();
            Guid secondResetId = Guid.NewGuid();

            CreatePasswordResetRequestDbResult? firstCreated = await passwordResetRepo.CreatePasswordResetRequestAsync(
                new CreatePasswordResetRequestDbCommand(
                    firstResetId,
                    accountId,
                    "email",
                    "email",
                    "repo-first-reset-code-hash",
                    1,
                    "repo-first-destination-fingerprint",
                    "r***e@example.com",
                    true,
                    false,
                    now.Plus(Duration.FromMinutes(10)),
                    5,
                    "127.0.0.1",
                    "repository-sql-replacement-test/first",
                    accountSecurityStamp),
                CancellationToken.None);

            firstCreated.ShouldNotBeNull();
            firstCreated.Result.ShouldBeTrue();
            firstCreated.Code.ShouldBe("PASSWORD_RESET_REQUEST_CREATED");
            firstCreated.PasswordResetRequestId.ShouldBe(firstResetId);

            CreatePasswordResetRequestDbResult? secondCreated = await passwordResetRepo.CreatePasswordResetRequestAsync(
                new CreatePasswordResetRequestDbCommand(
                    secondResetId,
                    accountId,
                    "email",
                    "email",
                    "repo-second-reset-code-hash",
                    1,
                    "repo-second-destination-fingerprint",
                    "r***e@example.com",
                    true,
                    false,
                    now.Plus(Duration.FromMinutes(20)),
                    5,
                    "127.0.0.1",
                    "repository-sql-replacement-test/second",
                    accountSecurityStamp),
                CancellationToken.None);

            secondCreated.ShouldNotBeNull();
            secondCreated.Result.ShouldBeTrue();
            secondCreated.Code.ShouldBe("PASSWORD_RESET_REQUEST_CREATED");
            secondCreated.PasswordResetRequestId.ShouldBe(secondResetId);

            PasswordResetFinalizeRecord? firstFinalize = await passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(firstResetId, CancellationToken.None);
            firstFinalize.ShouldNotBeNull();
            firstFinalize.Result.ShouldBeFalse();
            firstFinalize.Code.ShouldBe("PASSWORD_RESET_CANCELLED");
            firstFinalize.PasswordResetRequestId.ShouldBe(firstResetId);
            firstFinalize.CancelledAt.ShouldNotBeNull();

            PasswordResetFinalizeRecord? secondFinalize = await passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(secondResetId, CancellationToken.None);
            secondFinalize.ShouldNotBeNull();
            secondFinalize.Result.ShouldBeTrue();
            secondFinalize.Code.ShouldBe("PASSWORD_RESET_READY");
            secondFinalize.PasswordResetRequestId.ShouldBe(secondResetId);
            secondFinalize.KeyCodeHash.ShouldBe("repo-second-reset-code-hash");
            secondFinalize.CancelledAt.ShouldBeNull();

            (await QueryIntAsync(
                setupConnection,
                """
                select count(*)
                  from password_reset_requests
                 where account_id = @accountId
                   and consumed_at is null
                   and cancelled_at is null;
                """,
                ("accountId", accountId))).ShouldBe(1);

            (await QueryGuidAsync(
                setupConnection,
                """
                select password_reset_request_id
                  from password_reset_requests
                 where account_id = @accountId
                   and consumed_at is null
                   and cancelled_at is null;
                """,
                ("accountId", accountId))).ShouldBe(secondResetId);

            (await QueryIntAsync(
                setupConnection,
                """
                select count(*)
                  from password_reset_requests
                 where password_reset_request_id = @firstResetId
                   and cancelled_at is not null;
                """,
                ("firstResetId", firstResetId))).ShouldBe(1);
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }

    [Fact]
    public async Task PasswordResetRepo_cancel_request_marks_artifact_cancelled_against_real_sql()
    {
        string connectionString = RequiredConnectionString();
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "password_reset_cancel_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await CreateSchemaAndLoadBaseline(setupConnection, schema);

            Guid accountId = Guid.NewGuid();
            await ExecuteAsync(
                setupConnection,
                """
                insert into accounts(
                    account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                    login_failures, verify_status, features, two_factor_auth_method)
                values (
                    @accountId, 'repo-reset-cancel@example.com', 'repo-reset-cancel', @hashedPassword, 'repo-cancel-web-key', @saltOne, @siv, @nonce,
                    0, 1, 1, 0);
                """,
                ("accountId", accountId),
                ("hashedPassword", RepeatedByte(1, 128)),
                ("saltOne", RepeatedByte(2, 64)),
                ("siv", RepeatedByte(3, 32)),
                ("nonce", RepeatedByte(4, 16)));

            await ExecuteAsync(
                setupConnection,
                """
                insert into two_factor_authentications(
                    two_factor_index, account_id, method, verified, priority, required,
                    phone_number, phone_country_code)
                values(
                    1, @accountId, 2, true, 0, true,
                    '5555550100', '+1');
                """,
                ("accountId", accountId));
            // repo-reset-cancel-sms-factor
            Guid accountSecurityStamp = await QueryGuidAsync(
                setupConnection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            await using var storage = new SearchPathStorageContext(connectionString, schema);
            var passwordResetRepo = new PasswordResetRepo(storage, NullLogger<PasswordResetRepo>.Instance);

            Guid resetId = Guid.NewGuid();
            Instant now = Instant.FromUnixTimeSeconds(1_900_000_000);
            Instant cancelledAt = now.Plus(Duration.FromSeconds(30));

            CreatePasswordResetRequestDbResult? created = await passwordResetRepo.CreatePasswordResetRequestAsync(
                new CreatePasswordResetRequestDbCommand(
                    resetId,
                    accountId,
                    "sms",
                    "sms",
                    "repo-cancel-reset-code-hash",
                    1,
                    "repo-cancel-destination-fingerprint",
                    "+1******0100",
                    true,
                    false,
                    now.Plus(Duration.FromMinutes(10)),
                    5,
                    "127.0.0.1",
                    "repository-sql-cancel-test",
                    accountSecurityStamp),
                CancellationToken.None);

            created.ShouldNotBeNull();
            created.Result.ShouldBeTrue();
            created.Code.ShouldBe("PASSWORD_RESET_REQUEST_CREATED");

            CancelPasswordResetRequestResult? cancelled = await passwordResetRepo.CancelPasswordResetRequestAsync(
                resetId,
                cancelledAt,
                "PASSWORD_RESET_DELIVERY_FAILED",
                CancellationToken.None);

            cancelled.ShouldNotBeNull();
            cancelled.Result.ShouldBeTrue();
            cancelled.Code.ShouldBe("PASSWORD_RESET_DELIVERY_FAILED");
            cancelled.AccountId.ShouldBe(accountId);
            cancelled.CancelledAt.ShouldBe(cancelledAt);

            PasswordResetFinalizeRecord? finalizeRecord = await passwordResetRepo.GetPasswordResetRequestForFinalizeAsync(resetId, CancellationToken.None);
            finalizeRecord.ShouldNotBeNull();
            finalizeRecord.Result.ShouldBeFalse();
            finalizeRecord.Code.ShouldBe("PASSWORD_RESET_CANCELLED");
            finalizeRecord.PasswordResetRequestId.ShouldBe(resetId);
            finalizeRecord.CancelledAt.ShouldBe(cancelledAt);

            (await QueryIntAsync(
                setupConnection,
                """
                select count(*)
                  from password_reset_requests
                 where password_reset_request_id = @resetId
                   and cancelled_at is not null;
                """,
                ("resetId", resetId))).ShouldBe(1);

            (await QueryIntAsync(
                setupConnection,
                """
                select count(*)
                  from password_reset_events
                 where password_reset_request_id = @resetId
                   and event_type = 'password_reset_delivery_failed'
                   and code = 'PASSWORD_RESET_DELIVERY_FAILED';
                """,
                ("resetId", resetId))).ShouldBe(1);
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }


    [Fact]
    public async Task PasswordResetService_persists_selected_pending_session_against_real_sql()
    {
        string connectionString = RequiredConnectionString();
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "password_reset_session_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await CreateSchemaAndLoadBaseline(setupConnection, schema);
            Guid accountId = await InsertPasswordResetAccountWithSmsAndAuthenticator(setupConnection, "sql-reset-session-reader");

            await using SqlPasswordResetRuntime runtime = CreateSqlBackedPasswordResetRuntime(connectionString, schema);

            PasswordResetRequestResult request = await runtime.Service.RequestReset(
                new RequestPasswordResetCommand("sql-reset-session-reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "sql-session-persistence-test"),
                CancellationToken.None);

            request.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
            PasswordResetDeliveryCommand bootstrapDelivery = runtime.Delivery.LastDelivery.ShouldNotBeNull();
            bootstrapDelivery.ResetId.ShouldBe(request.ResetId);
            bootstrapDelivery.DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Email);

            PasswordResetVerifyResult verified = await runtime.Service.VerifyResetToken(
                new VerifyPasswordResetTokenCommand(request.ResetId, ResetCode, "192.0.2.10", "sql-session-persistence-test"),
                CancellationToken.None);

            verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
            verified.ResetAccessToken.ShouldNotBeNullOrWhiteSpace();
            verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);

            PasswordResetTwoFactorSelectResult selected = await runtime.Service.SelectTwoFactorConfiguration(
                new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, null, "192.0.2.10", "sql-session-persistence-test"),
                CancellationToken.None);

            selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);
            selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
            selected.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

            string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
            PasswordResetSession? persisted = await runtime.SessionService.GetSession(resetAccessTokenHash);
            persisted.ShouldNotBeNull();
            persisted.passwordResetRequestId.ShouldBe(request.ResetId);
            persisted.accountId.ShouldBe(accountId);
            persisted.resetAccessTokenHash.ShouldBe(resetAccessTokenHash);
            persisted.bootstrapProof.ShouldBe(PasswordResetBootstrapProof.EmailResetToken);
            persisted.state.ShouldBe(PasswordResetSessionState.AwaitingSmsCode);
            persisted.availableConfigurationsSnapshot.ShouldBe([
                TwoFactorAuthConfiguration.SMS,
                TwoFactorAuthConfiguration.AUTHENTICATOR_APP,
                TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP]);
            persisted.selectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
            persisted.requiredMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
            persisted.completedMethods.ShouldBeEmpty();
            persisted.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
            persisted.challengeCodeHash.ShouldNotBeNullOrWhiteSpace();
            persisted.challengeExpiration.ShouldNotBeNull();
            persisted.selectedAt.ShouldNotBeNull();
            persisted.expiresAt.ShouldBeGreaterThan(persisted.createdOn);

            (await QueryStringAsync(
                setupConnection,
                "select reset_access_token_hash from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", resetAccessTokenHash))).ShouldBe(resetAccessTokenHash);
            (await QueryGuidAsync(
                setupConnection,
                "select password_reset_request_id from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", resetAccessTokenHash))).ShouldBe(request.ResetId);
            (await QueryIntAsync(
                setupConnection,
                "select selected_two_factor_configuration from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", resetAccessTokenHash))).ShouldBe((int)TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
            (await QueryShortArrayAsync(
                setupConnection,
                "select required_methods from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", resetAccessTokenHash))).ShouldBe([(short)TwoFactorAuthMethod.SMS_KEY, (short)TwoFactorAuthMethod.AUTHENTICATOR_APP]);
            (await QueryShortArrayAsync(
                setupConnection,
                "select completed_methods from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", resetAccessTokenHash))).ShouldBeEmpty();
            (await QueryIntAsync(
                setupConnection,
                "select current_expected_method from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", resetAccessTokenHash))).ShouldBe((int)TwoFactorAuthMethod.SMS_KEY);
            (await QueryIntAsync(
                setupConnection,
                """
                select count(*)
                  from pending_password_reset_sessions
                 where reset_access_token_hash = @hash
                   and challenge_code_hash is not null
                   and challenge_expiration is not null
                   and selected_at is not null
                   and expires_at > created_on
                   and revoked_at is null;
                """,
                ("hash", resetAccessTokenHash))).ShouldBe(1);
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }

    [Fact]
    public async Task PasswordResetService_rehydrates_pending_session_with_fresh_sql_backed_service_instances()
    {
        string connectionString = RequiredConnectionString();
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "password_reset_rehydrate_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await CreateSchemaAndLoadBaseline(setupConnection, schema);
            await InsertPasswordResetAccountWithSmsAndAuthenticator(setupConnection, "sql-reset-rehydrate-reader");

            string resetAccessToken;
            string resetAccessTokenHash;
            Guid resetId;

            await using (SqlPasswordResetRuntime firstRuntime = CreateSqlBackedPasswordResetRuntime(connectionString, schema))
            {
                PasswordResetRequestResult request = await firstRuntime.Service.RequestReset(
                    new RequestPasswordResetCommand("sql-reset-rehydrate-reader@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "sql-rehydrate-test/first"),
                    CancellationToken.None);
                request.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
                resetId = request.ResetId;

                PasswordResetVerifyResult verified = await firstRuntime.Service.VerifyResetToken(
                    new VerifyPasswordResetTokenCommand(resetId, ResetCode, "192.0.2.10", "sql-rehydrate-test/first"),
                    CancellationToken.None);
                verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
                verified.ResetAccessToken.ShouldNotBeNullOrWhiteSpace();
                resetAccessToken = verified.ResetAccessToken!;
                resetAccessTokenHash = AccessTokenHashUtility.Hash(resetAccessToken);

                PasswordResetTwoFactorSelectResult selected = await firstRuntime.Service.SelectTwoFactorConfiguration(
                    new SelectPasswordResetTwoFactorConfigurationCommand(resetAccessToken, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, null, "192.0.2.10", "sql-rehydrate-test/first"),
                    CancellationToken.None);
                selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);
                selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
            }

            await using (SqlPasswordResetRuntime secondRuntime = CreateSqlBackedPasswordResetRuntime(connectionString, schema))
            {
                PasswordResetTwoFactorVerifyResult smsProof = await secondRuntime.Service.VerifyTwoFactorProof(
                    new VerifyPasswordResetTwoFactorCommand(resetAccessToken, TwoFactorAuthMethod.SMS_KEY, ResetCode, "192.0.2.10", "sql-rehydrate-test/second"),
                    CancellationToken.None);

                smsProof.Code.ShouldBe(PasswordResetService.TwoFactorProofAcceptedNextProofRequiredCode);
                smsProof.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
                smsProof.CompletedTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
                smsProof.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
                smsProof.CanChangePassword.ShouldBeFalse();

                PasswordResetSession? afterSms = await secondRuntime.SessionService.GetSession(resetAccessTokenHash);
                afterSms.ShouldNotBeNull();
                afterSms.passwordResetRequestId.ShouldBe(resetId);
                afterSms.state.ShouldBe(PasswordResetSessionState.AwaitingAuthenticatorCode);
                afterSms.completedMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
                afterSms.currentExpectedMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
            }

            await using (SqlPasswordResetRuntime thirdRuntime = CreateSqlBackedPasswordResetRuntime(connectionString, schema))
            {
                PasswordResetTwoFactorVerifyResult authenticatorProof = await thirdRuntime.Service.VerifyTwoFactorProof(
                    new VerifyPasswordResetTwoFactorCommand(resetAccessToken, TwoFactorAuthMethod.AUTHENTICATOR_APP, ValidTotpCode, "192.0.2.10", "sql-rehydrate-test/third"),
                    CancellationToken.None);

                authenticatorProof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);
                authenticatorProof.CurrentRequiredMethod.ShouldBeNull();
                authenticatorProof.CompletedTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
                authenticatorProof.RemainingTwoFactorAuthMethods.ShouldBeEmpty();
                authenticatorProof.CanChangePassword.ShouldBeTrue();

                PasswordResetSession? afterAuthenticator = await thirdRuntime.SessionService.GetSession(resetAccessTokenHash);
                afterAuthenticator.ShouldNotBeNull();
                afterAuthenticator.passwordResetRequestId.ShouldBe(resetId);
                afterAuthenticator.state.ShouldBe(PasswordResetSessionState.TwoFactorComplete);
                afterAuthenticator.twoFactorCompletedAt.ShouldNotBeNull();
                afterAuthenticator.completedMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
                afterAuthenticator.currentExpectedMethod.ShouldBeNull();
            }
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }

    [Fact]
    public async Task PasswordResetRepo_revokes_pending_sessions_on_terminal_reset_events_against_real_sql()
    {
        string connectionString = RequiredConnectionString();
        await using var setupConnection = new NpgsqlConnection(connectionString);
        await setupConnection.OpenAsync();

        string schema = "password_reset_terminal_session_contract_" + Guid.NewGuid().ToString("N");

        try
        {
            await CreateSchemaAndLoadBaseline(setupConnection, schema);
            Guid accountId = await InsertPasswordResetAccountWithSmsAndAuthenticator(setupConnection, "sql-reset-terminal-reader");
            Guid accountSecurityStamp = await QueryGuidAsync(
                setupConnection,
                "select security_stamp from accounts where account_id = @accountId;",
                ("accountId", accountId));

            await using var storage = new SearchPathStorageContext(connectionString, schema);
            var passwordResetRepo = new PasswordResetRepo(storage, NullLogger<PasswordResetRepo>.Instance);
            var sessionService = new PasswordResetSessionService(passwordResetRepo);
            Instant now = SystemClock.Instance.GetCurrentInstant();

            Guid completedResetId = Guid.NewGuid();
            string completedHash = "terminal-completed-session-hash";
            await CreateRepoReset(passwordResetRepo, completedResetId, accountId, accountSecurityStamp, now.Plus(Duration.FromMinutes(10)), "terminal-completed-code-hash");
            await SavePendingSession(sessionService, completedResetId, accountId, completedHash, now);

            PromotePasswordResetResult? promoted = await passwordResetRepo.PromotePasswordResetAsync(
                new PromotePasswordResetDbCommand(
                    completedResetId,
                    accountId,
                    RepeatedByte(9, AccountCryptoSizes.PasswordHashBytes),
                    RepeatedByte(8, AccountCryptoSizes.SaltOneBytes),
                    RepeatedByte(7, AccountCryptoSizes.SivBytes),
                    RepeatedByte(6, AccountCryptoSizes.NonceBytes),
                    Guid.NewGuid(),
                    now.Plus(Duration.FromSeconds(5))),
                CancellationToken.None);

            promoted.ShouldNotBeNull();
            promoted.Result.ShouldBeTrue();
            promoted.Code.ShouldBe(PasswordResetService.CompletedCode);
            (await sessionService.GetSession(completedHash)).ShouldBeNull();
            (await QueryStringAsync(
                setupConnection,
                "select revoked_reason from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", completedHash))).ShouldBe(PasswordResetService.CompletedCode);

            promoted.AccountSecurityStamp.ShouldNotBeNull();
            accountSecurityStamp = promoted.AccountSecurityStamp.Value;
            Guid cancelledResetId = Guid.NewGuid();
            string cancelledHash = "terminal-cancelled-session-hash";
            await CreateRepoReset(passwordResetRepo, cancelledResetId, accountId, accountSecurityStamp, now.Plus(Duration.FromMinutes(20)), "terminal-cancelled-code-hash");
            await SavePendingSession(sessionService, cancelledResetId, accountId, cancelledHash, now.Plus(Duration.FromSeconds(10)));

            CancelPasswordResetRequestResult? cancelled = await passwordResetRepo.CancelPasswordResetRequestAsync(
                cancelledResetId,
                now.Plus(Duration.FromSeconds(20)),
                PasswordResetService.DeliveryFailedCode,
                CancellationToken.None);

            cancelled.ShouldNotBeNull();
            cancelled.Result.ShouldBeTrue();
            cancelled.Code.ShouldBe(PasswordResetService.DeliveryFailedCode);
            (await sessionService.GetSession(cancelledHash)).ShouldBeNull();
            (await QueryStringAsync(
                setupConnection,
                "select revoked_reason from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", cancelledHash))).ShouldBe(PasswordResetService.DeliveryFailedCode);

            Guid expiredResetId = Guid.NewGuid();
            string expiredHash = "terminal-expired-session-hash";
            Instant expiredAt = now.Plus(Duration.FromMinutes(1));
            await CreateRepoReset(passwordResetRepo, expiredResetId, accountId, accountSecurityStamp, expiredAt, "terminal-expired-code-hash");
            await SavePendingSession(sessionService, expiredResetId, accountId, expiredHash, now.Plus(Duration.FromSeconds(30)));

            PasswordResetCleanupResult? cleanup = await passwordResetRepo.CleanupExpiredPasswordResetRequestsAsync(
                expiredAt.Plus(Duration.FromSeconds(1)),
                Period.FromDays(30),
                CancellationToken.None);

            cleanup.ShouldNotBeNull();
            cleanup.Result.ShouldBeTrue();
            cleanup.Code.ShouldBe("PASSWORD_RESET_CLEANUP_COMPLETED");
            cleanup.CancelledCount.ShouldBeGreaterThanOrEqualTo(1);
            (await sessionService.GetSession(expiredHash)).ShouldBeNull();
            (await QueryStringAsync(
                setupConnection,
                "select revoked_reason from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", expiredHash))).ShouldBe(PasswordResetService.ExpiredCode);


            Guid methodRemovalResetId = Guid.NewGuid();
            string methodRemovalHash = "terminal-method-removal-session-hash";
            await CreateRepoReset(passwordResetRepo, methodRemovalResetId, accountId, accountSecurityStamp, now.Plus(Duration.FromMinutes(30)), "terminal-method-removal-code-hash");
            await SavePendingSession(sessionService, methodRemovalResetId, accountId, methodRemovalHash, now.Plus(Duration.FromSeconds(40)));

            await ExecuteAsync(
                setupConnection,
                "select * from revoke_pending_password_reset_sessions_for_account(@accountId, now(), 'TWO_FACTOR_METHOD_REMOVED');",
                ("accountId", accountId));

            (await sessionService.GetSession(methodRemovalHash)).ShouldBeNull();
            (await QueryStringAsync(
                setupConnection,
                "select revoked_reason from pending_password_reset_sessions where reset_access_token_hash = @hash;",
                ("hash", methodRemovalHash))).ShouldBe("TWO_FACTOR_METHOD_REMOVED");
        }
        finally
        {
            await ExecuteAsync(setupConnection, $"drop schema if exists {schema} cascade;");
        }
    }

    private static string RequiredConnectionString()
    {
        if (!DeferredSqlProcedureContractSettings.ShouldRun())
        {
            throw new InvalidOperationException(DeferredSqlProcedureContractSettings.SkipReason);
        }

        return DeferredSqlProcedureContractSettings.ConnectionString!;
    }

    private static async Task CreateSchemaAndLoadBaseline(NpgsqlConnection connection, string schema)
    {
        await ExecuteAsync(connection, $"create schema {schema};");
        await ExecuteAsync(connection, $"set search_path to {schema};");
        await ExecuteAsync(connection, File.ReadAllText(BaselinePath()));
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

    private static async Task<int> QueryIntAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return Convert.ToInt32(result);
    }

    private static async Task<byte[]> QueryBytesAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (byte[])result;
    }


    private static async Task<string> QueryStringAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (string)result;
    }

    private static async Task<short[]> QueryShortArrayAsync(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        AddParameters(command, parameters);
        object? result = await command.ExecuteScalarAsync();
        result.ShouldNotBeNull();
        return (short[])result;
    }

    private static async Task<Guid> InsertPasswordResetAccountWithSmsAndAuthenticator(NpgsqlConnection connection, string accountSlug)
    {
        Guid accountId = Guid.NewGuid();
        string emailAddress = accountSlug + "@example.com";
        string username = accountSlug;

        await ExecuteAsync(
            connection,
            """
            insert into accounts(
                account_id, email_address, username, hashed_password, web_key, salt_one, siv, nonce,
                login_failures, verify_status, features, two_factor_auth_method)
            values (
                @accountId, @emailAddress, @username, @hashedPassword, @webKey, @saltOne, @siv, @nonce,
                0, 1, 1, 6);

            insert into two_factor_authentications(
                two_factor_index, account_id, method, verified, priority, required,
                phone_number, phone_country_code)
            values(
                1, @accountId, 2, true, 0, true,
                '5555550101', '+1');

            insert into two_factor_authentications(
                two_factor_index, account_id, method, verified, priority, required,
                totp_secret_ciphertext, totp_secret_nonce, totp_secret_tag, totp_secret_version)
            values(
                2, @accountId, 3, true, 1, true,
                @ciphertext, @totpNonce, @tag, 1);
            """,
            ("accountId", accountId),
            ("emailAddress", emailAddress),
            ("username", username),
            ("hashedPassword", RepeatedByte(1, AccountCryptoSizes.PasswordHashBytes)),
            ("webKey", "sql-password-reset-web-key-" + accountSlug),
            ("saltOne", RepeatedByte(2, AccountCryptoSizes.SaltOneBytes)),
            ("siv", RepeatedByte(3, AccountCryptoSizes.SivBytes)),
            ("nonce", RepeatedByte(4, AccountCryptoSizes.NonceBytes)),
            ("ciphertext", new byte[] { 0xAA, 0x01, 0x02 }),
            ("totpNonce", new byte[] { 0xBB, 0x03, 0x04 }),
            ("tag", new byte[] { 0xCC, 0x05, 0x06 }));

        return accountId;
    }

    private static SqlPasswordResetRuntime CreateSqlBackedPasswordResetRuntime(string connectionString, string schema)
    {
        var storage = new SearchPathStorageContext(connectionString, schema);
        var repo = new PasswordResetRepo(storage, NullLogger<PasswordResetRepo>.Instance);
        var sessionService = new PasswordResetSessionService(repo);
        var settings = TestPasswordResetSettings();
        var codeHasher = new PasswordResetCodeHasher(Options.Create(settings));
        var delivery = new CapturingPasswordResetDeliveryService();

        var service = new PasswordResetService(
            repo,
            new FixedPasswordResetCodeGenerator(ResetCode),
            codeHasher,
            new PasswordResetRateLimitKeyFactory(Options.Create(settings)),
            new PasswordResetAbusePolicy(Options.Create(settings)),
            new PasswordResetAbuseCounterKeyFactory(Options.Create(settings)),
            new AllowingAbuseCounterStore(),
            Options.Create(new AbuseControlSettings
            {
                PasswordReset = new PasswordResetAbusePolicySettings { Enabled = false }
            }),
            delivery,
            new FixedPasswordResetTotpVerifier(ValidTotpCode),
            new FixedPasswordMaterialFactory(),
            Options.Create(settings),
            Options.Create(new RegistrationSettings
            {
                MinUsernameLength = 3,
                MaxUsernameLength = 64,
                MinPasswordLength = 8,
                MaxPasswordLength = 128,
                MaxEmailAddressLength = 255,
                AccountMetaDataRetries = 3,
                VerifyAccountPeriodDays = 1,
                EmailChangeVerifyPeriodDays = 1,
                AccountDeleteTokenPeriodDays = 1
            }),
            NullLogger<PasswordResetService>.Instance,
            sessionService);

        return new SqlPasswordResetRuntime(storage, service, sessionService, delivery);
    }

    private static PasswordResetSettings TestPasswordResetSettings()
    {
        return new PasswordResetSettings
        {
            CodeLength = 8,
            CodeHashPepper = "sql-contract-password-reset-pepper",
            ExpirationMinutes = 2,
            MaxAttempts = 5,
            RequestCooldownSeconds = 0,
            DailyRequestLimitPerAccount = 100,
            DailyRequestLimitPerDestination = 100,
            DailyRequestLimitPerIp = 100,
            DailyRequestWindowHours = 24,
            RateLimitBlockMinutes = 30,
            CaptchaChallengeEnabled = false,
            CaptchaChallengeAfterRequests = 3
        };
    }

    private static async Task CreateRepoReset(
        IPasswordResetRepo repo,
        Guid resetId,
        Guid accountId,
        Guid accountSecurityStamp,
        Instant expiresAt,
        string codeHash)
    {
        CreatePasswordResetRequestDbResult? created = await repo.CreatePasswordResetRequestAsync(
            new CreatePasswordResetRequestDbCommand(
                resetId,
                accountId,
                PasswordResetDeliveryChannels.Email,
                PasswordResetDeliveryChannels.Email,
                codeHash,
                1,
                "terminal-session-destination-" + resetId.ToString("N"),
                "t***l@example.com",
                true,
                false,
                expiresAt,
                5,
                "127.0.0.1",
                "repository-sql-terminal-session-test",
                accountSecurityStamp),
            CancellationToken.None);

        created.ShouldNotBeNull();
        created.Result.ShouldBeTrue();
        created.Code.ShouldBe("PASSWORD_RESET_REQUEST_CREATED");
        created.PasswordResetRequestId.ShouldBe(resetId);
    }

    private static async Task SavePendingSession(
        PasswordResetSessionService sessionService,
        Guid resetId,
        Guid accountId,
        string resetAccessTokenHash,
        Instant createdOn)
    {
        var session = new PasswordResetSession(
            accountId,
            resetAccessTokenHash,
            PasswordResetBootstrapProof.EmailResetToken,
            [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP],
            createdOn,
            createdOn.Plus(Duration.FromMinutes(10)),
            PasswordResetSessionState.TwoFactorSelectionRequired,
            resetId);

        session.SelectConfiguration(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP, createdOn.Plus(Duration.FromSeconds(1)));
        session.StartChallenge("terminal-session-challenge-hash-" + resetId.ToString("N"), createdOn.Plus(Duration.FromMinutes(2)), createdOn.Plus(Duration.FromSeconds(2)));

        bool? saved = await sessionService.SetSession(resetAccessTokenHash, session, TimeSpan.FromMinutes(10));
        saved.ShouldNotBeNull();
        saved.Value.ShouldBeTrue();
    }

    private static void AddParameters(NpgsqlCommand command, params (string Name, object? Value)[] parameters)
    {
        foreach ((string name, object? value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }
    }

    private static byte[] RepeatedByte(byte value, int count)
    {
        return Enumerable.Repeat(value, count).ToArray();
    }

    private static string BaselinePath()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return Path.Combine(directory.FullName, "Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql");
    }


    private sealed class SqlPasswordResetRuntime : IAsyncDisposable
    {
        private readonly SearchPathStorageContext _storage;

        public SqlPasswordResetRuntime(
            SearchPathStorageContext storage,
            PasswordResetService service,
            PasswordResetSessionService sessionService,
            CapturingPasswordResetDeliveryService delivery)
        {
            _storage = storage;
            Service = service;
            SessionService = sessionService;
            Delivery = delivery;
        }

        public PasswordResetService Service { get; }

        public PasswordResetSessionService SessionService { get; }

        public CapturingPasswordResetDeliveryService Delivery { get; }

        public async ValueTask DisposeAsync()
        {
            await _storage.DisposeAsync();
        }
    }

    private sealed class CapturingPasswordResetDeliveryService : IPasswordResetDeliveryService
    {
        public List<PasswordResetDeliveryCommand> Deliveries { get; } = [];

        public PasswordResetDeliveryCommand? LastDelivery => Deliveries.LastOrDefault();

        public Task<PasswordResetDeliveryResult> SendPasswordResetCode(
            PasswordResetDeliveryCommand command,
            CancellationToken cancellationToken)
        {
            Deliveries.Add(command);
            return Task.FromResult(new PasswordResetDeliveryResult(true, PasswordResetDeliveryService.SentCode));
        }
    }

    private sealed class FixedPasswordResetCodeGenerator : IPasswordResetCodeGenerator
    {
        private readonly string _code;

        public FixedPasswordResetCodeGenerator(string code)
        {
            _code = code;
        }

        public string GenerateKeyCode()
        {
            return _code;
        }
    }

    private sealed class FixedPasswordResetTotpVerifier : IPasswordResetTotpVerifier
    {
        private readonly string _validTotp;

        public FixedPasswordResetTotpVerifier(string validTotp)
        {
            _validTotp = validTotp;
        }

        public Task<PasswordResetTotpVerificationResult> VerifyTotpForPasswordReset(
            Guid accountId,
            string totpCode,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(string.Equals(totpCode, _validTotp, StringComparison.Ordinal)
                ? PasswordResetTotpVerificationResult.Success()
                : PasswordResetTotpVerificationResult.Failed("PASSWORD_RESET_TOTP_INVALID"));
        }
    }

    private sealed class FixedPasswordMaterialFactory : IPasswordResetPasswordMaterialFactory
    {
        public PasswordResetPasswordMaterial CreatePasswordMaterial(string password)
        {
            return new PasswordResetPasswordMaterial(
                RepeatedByte(9, AccountCryptoSizes.PasswordHashBytes),
                RepeatedByte(8, AccountCryptoSizes.SaltOneBytes),
                RepeatedByte(7, AccountCryptoSizes.SivBytes),
                RepeatedByte(6, AccountCryptoSizes.NonceBytes));
        }
    }

    private sealed class AllowingAbuseCounterStore : IAbuseCounterStore
    {
        public Task<CounterDecision> IncrementAsync(
            AbuseCounterKey key,
            AbuseCounterLimit limit,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CounterDecision(true, 1, limit.MaxAttempts, limit.Window, null, null));
        }

        public Task ResetAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<CooldownDecision> GetCooldownAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CooldownDecision(false, null, null));
        }
    }

    private sealed class SearchPathStorageContext : StorageContext, IAsyncDisposable
    {
        private readonly NpgsqlDataSource _dataSource;
        private readonly string _schema;

        public SearchPathStorageContext(string connectionString, string schema)
            : base(Options.Create(new DatabaseSettings
            {
                servers = "localhost",
                database = "treehammock_tests",
                userId = "treehammock",
                password = "test-password",
                lc_collation = "en_US.UTF-8"
            }))
        {
            var dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
            dataSourceBuilder.UseNodaTime();
            _dataSource = dataSourceBuilder.Build();
            _schema = schema;
        }

        public override async Task<NpgsqlConnection> CreateConnection()
        {
            NpgsqlConnection connection = await _dataSource.OpenConnectionAsync();
            await using var command = new NpgsqlCommand($"set search_path to {_schema};", connection);
            await command.ExecuteNonQueryAsync();
            return connection;
        }

        public async ValueTask DisposeAsync()
        {
            await _dataSource.DisposeAsync();
        }
    }
}
