using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Models.PasswordReset;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetTotpFinalizeTests
{
    [Fact]
    public async Task VerifyResetToken_returns_selection_required_when_email_reset_requires_totp()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult result = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        result.Status.ShouldBe("two_factor_selection_required");
        result.ResetAccessToken.ShouldNotBeNull();
        result.ResetAccessToken!.ShouldStartWith(resetId.ToString("N") + ".");
        result.RequiresTwoFactor.ShouldBeTrue();
        result.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task VerifyResetToken_returns_verified_when_no_reset_eligible_2fa_exists()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult result = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TokenVerifiedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        result.Status.ShouldBe("verified");
        result.ResetAccessToken.ShouldNotBeNull();
        result.RequiresTwoFactor.ShouldBeFalse();
        result.AvailableTwoFactorAuthConfigurations.ShouldBeEmpty();
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_persists_authenticator_session_when_reset_access_token_is_valid()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        harness.PasswordResetSessionService.SetSession(Arg.Any<string>(), Arg.Any<PasswordResetSession>(), Arg.Any<TimeSpan>())
            .Returns(Task.FromResult<bool?>(true));

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status200OK);
        selected.Status.ShouldBe("authenticator_code_required");
        selected.ResetAccessToken.ShouldBe(verified.ResetAccessToken);
        selected.SelectedConfiguration.ShouldBe(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        selected.CompletedTwoFactorAuthMethods.ShouldBeEmpty();
        selected.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        selected.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        selected.CanChangePassword.ShouldBeFalse();
        await harness.PasswordResetSessionService.Received(1).SetSession(
            AccessTokenHashUtility.Hash(verified.ResetAccessToken!),
            Arg.Is<PasswordResetSession>(session =>
                session.accountId == accountId
                && session.selectedConfiguration == TwoFactorAuthConfiguration.AUTHENTICATOR_APP
                && session.currentExpectedMethod == TwoFactorAuthMethod.AUTHENTICATOR_APP
                && session.state == PasswordResetSessionState.AwaitingAuthenticatorCode),
            Arg.Any<TimeSpan>());
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_rejects_configuration_not_in_verified_snapshot()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, TwoFactorAuthConfiguration.SMS, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorConfigurationNotAvailableCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        selected.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        await harness.PasswordResetSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task SelectTwoFactorConfiguration_rejects_tampered_reset_access_token()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true, method: PasswordResetDeliveryChannels.Email);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        string tamperedToken = verified.ResetAccessToken![..^1] + (verified.ResetAccessToken.EndsWith("0", StringComparison.Ordinal) ? "1" : "0");
        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(tamperedToken, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        selected.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        await harness.PasswordResetSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default);
    }

    [Fact]
    public async Task VerifyResetToken_registers_failed_attempt_when_key_code_is_wrong()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "00000000", "stored-hash").Returns(false);
        harness.Repo.RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                true,
                "PASSWORD_RESET_ATTEMPT_RECORDED",
                accountId,
                1,
                5,
                null)));

        PasswordResetVerifyResult result = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "00000000", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        result.ResetAccessToken.ShouldBeNull();
        result.RequiresTwoFactor.ShouldBeFalse();
        await harness.Repo.Received(1).RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeReset_requires_reset_twofactor_flow_when_mock_totp_reset_has_verified_key_code()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorRequiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_rejects_mock_totp_proof_even_when_totp_code_is_supplied()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorRequiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_promotes_password_when_reset_access_token_session_is_complete()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        harness.AllowPromotion(resetId, accountId);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);
        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = new PasswordResetSession(
            accountId,
            resetAccessTokenHash,
            PasswordResetBootstrapProof.EmailResetToken,
            [TwoFactorAuthConfiguration.AUTHENTICATOR_APP],
            now,
            now.Plus(Duration.FromMinutes(10)));
        session.SelectConfiguration(TwoFactorAuthConfiguration.AUTHENTICATOR_APP, now);
        session.MarkCurrentProofAccepted();
        session.MarkTwoFactorComplete(now);
        harness.PasswordResetSessionService.GetSession(resetAccessTokenHash)
            .Returns(Task.FromResult<PasswordResetSession?>(session));
        harness.PasswordResetSessionService.RevokeSession(resetAccessTokenHash)
            .Returns(Task.FromResult(true));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(Guid.Empty, null, null, "new-password", "new-password", "192.0.2.10", "unit-test", verified.ResetAccessToken),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.CompletedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.Received(1).PromotePasswordResetAsync(
            Arg.Is<PromotePasswordResetDbCommand>(command =>
                command.PasswordResetRequestId == resetId
                && command.AccountId == accountId
                && command.HashedPassword.Length == AccountCryptoSizes.PasswordHashBytes
                && command.SaltOne.Length == AccountCryptoSizes.SaltOneBytes
                && command.Siv.Length == AccountCryptoSizes.SivBytes
                && command.Nonce.Length == AccountCryptoSizes.NonceBytes),
            Arg.Any<CancellationToken>());
        await harness.PasswordResetSessionService.Received(1).RevokeSession(resetAccessTokenHash);
    }

    [Fact]
    public async Task FinalizeReset_rejects_reset_access_token_until_reset_twofactor_session_is_complete()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(resetId, "49382710", "192.0.2.10", "unit-test"),
            CancellationToken.None);
        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var session = new PasswordResetSession(
            accountId,
            resetAccessTokenHash,
            PasswordResetBootstrapProof.EmailResetToken,
            [TwoFactorAuthConfiguration.AUTHENTICATOR_APP],
            now,
            now.Plus(Duration.FromMinutes(10)));
        session.SelectConfiguration(TwoFactorAuthConfiguration.AUTHENTICATOR_APP, now);
        harness.PasswordResetSessionService.GetSession(resetAccessTokenHash)
            .Returns(Task.FromResult<PasswordResetSession?>(session));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(Guid.Empty, null, null, "new-password", "new-password", "192.0.2.10", "unit-test", verified.ResetAccessToken),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorNotCompleteCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_does_not_require_totp_for_non_totp_reset()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        harness.AllowPromotion(resetId, accountId);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.CompletedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }

    [Fact]
    public async Task FinalizeReset_registers_failed_attempt_when_key_code_is_wrong()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: true);
        harness.Hasher.VerifyCode(resetId, "00000000", "stored-hash").Returns(false);
        harness.Repo.RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                false,
                PasswordResetService.AttemptsExceededCode,
                accountId,
                5,
                5,
                SystemClock.Instance.GetCurrentInstant())));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "00000000", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.AttemptsExceededCode);
        result.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }


    [Fact]
    public async Task FinalizeReset_rejects_mock_totp_only_reset_without_key_code_requirement()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(
            resetId,
            accountId,
            method: "authenticator_app_totp",
            requiresKeyCode: false,
            requiresTotp: true,
            deliveryChannel: null,
            keyCodeHash: null);
        harness.Repo.RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                true,
                "PASSWORD_RESET_ATTEMPT_RECORDED",
                accountId,
                1,
                5,
                null)));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, null, "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
        await harness.Repo.Received(1).RegisterFailedAttemptAsync(resetId, Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_requires_key_code_when_reset_row_requires_key_code()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, null, null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.ValidationFailedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.Repo.DidNotReceiveWithAnyArgs().RegisterFailedAttemptAsync(default, default, default);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_rejects_password_that_fails_configured_length_policy_before_promotion()
    {
        Harness harness = CreateHarness();
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "short", "short", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.ValidationFailedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        await harness.Repo.DidNotReceiveWithAnyArgs().PromotePasswordResetAsync(default!, default);
    }

    [Fact]
    public async Task FinalizeReset_throttles_per_reset_id_before_lookup()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        Guid resetId = Guid.NewGuid();
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key =>
                    key.Feature == AbuseFeature.PasswordResetFinalize
                    && key.Dimension == AbuseCounterDimension.Reset),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    false,
                    limit.MaxAttempts + 1,
                    limit.MaxAttempts,
                    limit.Window,
                    TimeSpan.FromMinutes(15),
                    AbuseReasonCodes.PasswordResetFinalizeThrottleExceeded));
            });

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.AttemptsExceededCode);
        result.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        await harness.Repo.DidNotReceiveWithAnyArgs().GetPasswordResetRequestForFinalizeAsync(default, default);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }

    [Fact]
    public async Task FinalizeReset_fails_closed_before_lookup_when_abuse_counter_store_is_unavailable()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        Guid resetId = Guid.NewGuid();
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key =>
                    key.Feature == AbuseFeature.PasswordResetFinalize
                    && key.Dimension == AbuseCounterDimension.Reset),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    false,
                    0,
                    limit.MaxAttempts,
                    limit.Window,
                    null,
                    AbuseReasonCodes.CounterStoreUnavailable));
            });

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", "123456", "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.AbuseCounterUnavailableCode);
        result.StatusCode.ShouldBe(StatusCodes.Status503ServiceUnavailable);
        await harness.Repo.DidNotReceiveWithAnyArgs().GetPasswordResetRequestForFinalizeAsync(default, default);
        harness.Hasher.DidNotReceiveWithAnyArgs().VerifyCode(default, default!, default!);
        await harness.TotpVerifier.DidNotReceiveWithAnyArgs().VerifyTotpForPasswordReset(default, default!, default);
    }

    [Fact]
    public async Task FinalizeReset_resets_finalize_abuse_counter_after_successful_promotion()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        Guid resetId = Guid.NewGuid();
        Guid accountId = Guid.NewGuid();
        harness.ReadyReset(resetId, accountId, requiresTotp: false);
        harness.Hasher.VerifyCode(resetId, "49382710", "stored-hash").Returns(true);
        harness.AllowPromotion(resetId, accountId);

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.CompletedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status200OK);
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key =>
                key.Feature == AbuseFeature.PasswordResetFinalize
                && key.Dimension == AbuseCounterDimension.Reset
                && !key.Value.Contains(resetId.ToString("N"), StringComparison.OrdinalIgnoreCase)),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeReset_abuse_limit_uses_configured_attempt_window_and_cooldown()
    {
        Harness harness = CreateHarness();
        harness.AbuseControlSettings.PasswordReset.Enabled = true;
        harness.AbuseControlSettings.PasswordReset.MaxFinalizeAttemptsPerResetId = 7;
        harness.AbuseControlSettings.PasswordReset.FinalizeAttemptWindowSeconds = 1200;
        harness.AbuseControlSettings.PasswordReset.CooldownSecondsAfterExhaustion = 1800;
        Guid resetId = Guid.NewGuid();
        AbuseCounterLimit? capturedLimit = null;
        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.PasswordResetFinalize),
                Arg.Do<AbuseCounterLimit>(limit => capturedLimit = limit),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(true, 1, limit.MaxAttempts, limit.Window, null, null));
            });
        harness.Repo.GetPasswordResetRequestForFinalizeAsync(resetId, Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<PasswordResetFinalizeRecord?>(new PasswordResetFinalizeRecord(
                false,
                PasswordResetService.AttemptsExceededCode,
                resetId,
                Guid.NewGuid(),
                PasswordResetDeliveryChannels.Email,
                "email",
                "stored-hash",
                1,
                true,
                false,
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
                null,
                null,
                7,
                7,
                Guid.NewGuid())));

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(resetId, "49382710", null, "new-password", "new-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.AttemptsExceededCode);
        capturedLimit.ShouldNotBeNull();
        capturedLimit!.MaxAttempts.ShouldBe(7);
        capturedLimit.Window.ShouldBe(TimeSpan.FromSeconds(1200));
        capturedLimit.Cooldown.ShouldBe(TimeSpan.FromSeconds(1800));
    }

    private static Harness CreateHarness()
    {
        var repo = Substitute.For<IPasswordResetRepo>();
        var generator = Substitute.For<IPasswordResetCodeGenerator>();
        var hasher = Substitute.For<IPasswordResetCodeHasher>();
        var delivery = Substitute.For<IPasswordResetDeliveryService>();
        var totpVerifier = Substitute.For<IPasswordResetTotpVerifier>();
        var passwordMaterialFactory = Substitute.For<IPasswordResetPasswordMaterialFactory>();
        var passwordResetSessionService = Substitute.For<IPasswordResetSessionService>();
        PasswordResetSettings settings = Settings();
        var keyFactory = new PasswordResetRateLimitKeyFactory(Options.Create(settings));
        var abusePolicy = new PasswordResetAbusePolicy(Options.Create(settings));
        var abuseCounterKeyFactory = new PasswordResetAbuseCounterKeyFactory(Options.Create(settings));
        var abuseCounterStore = Substitute.For<IAbuseCounterStore>();
        AbuseControlSettings abuseControlSettings = new()
        {
            PasswordReset = new PasswordResetAbusePolicySettings { Enabled = false }
        };
        abuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    true,
                    1,
                    limit.MaxAttempts,
                    limit.Window,
                    null,
                    null));
            });
        abuseCounterStore.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        var service = new PasswordResetService(
            repo,
            generator,
            hasher,
            keyFactory,
            abusePolicy,
            abuseCounterKeyFactory,
            abuseCounterStore,
            Options.Create(abuseControlSettings),
            delivery,
            totpVerifier,
            passwordMaterialFactory,
            Options.Create(settings),
            Options.Create(RegistrationSettings()),
            NullLogger<PasswordResetService>.Instance,
            passwordResetSessionService);

        return new Harness(service, repo, hasher, totpVerifier, passwordMaterialFactory, passwordResetSessionService, abuseCounterStore, abuseControlSettings);
    }

    private static PasswordResetSettings Settings()
    {
        return new PasswordResetSettings
        {
            CodeLength = 8,
            CodeHashPepper = "unit-test-password-reset-pepper",
            ExpirationMinutes = 2,
            MaxAttempts = 5,
            RequestCooldownSeconds = 60,
            DailyRequestLimitPerAccount = 5,
            DailyRequestLimitPerDestination = 5,
            DailyRequestLimitPerIp = 20,
            DailyRequestWindowHours = 24,
            RateLimitBlockMinutes = 30,
            CaptchaChallengeEnabled = false,
            CaptchaChallengeAfterRequests = 3
        };
    }

    private static RegistrationSettings RegistrationSettings()
    {
        return new RegistrationSettings
        {
            MinUsernameLength = 3,
            MaxUsernameLength = 30,
            MinPasswordLength = 8,
            MaxPasswordLength = 128,
            MaxEmailAddressLength = 255,
            AccountMetaDataRetries = 3,
            VerifyAccountPeriodDays = 1,
            EmailChangeVerifyPeriodDays = 1,
            AccountDeleteTokenPeriodDays = 1
        };
    }

    private sealed record Harness(
        PasswordResetService Service,
        IPasswordResetRepo Repo,
        IPasswordResetCodeHasher Hasher,
        IPasswordResetTotpVerifier TotpVerifier,
        IPasswordResetPasswordMaterialFactory PasswordMaterialFactory,
        IPasswordResetSessionService PasswordResetSessionService,
        IAbuseCounterStore AbuseCounterStore,
        AbuseControlSettings AbuseControlSettings)
    {
        public void AllowPromotion(Guid resetId, Guid accountId)
        {
            PasswordMaterialFactory.CreatePasswordMaterial(Arg.Any<string>())
                .Returns(new PasswordResetPasswordMaterial(
                    Enumerable.Repeat((byte)1, AccountCryptoSizes.PasswordHashBytes).ToArray(),
                    Enumerable.Repeat((byte)2, AccountCryptoSizes.SaltOneBytes).ToArray(),
                    Enumerable.Repeat((byte)3, AccountCryptoSizes.SivBytes).ToArray(),
                    Enumerable.Repeat((byte)4, AccountCryptoSizes.NonceBytes).ToArray()));

            Repo.PromotePasswordResetAsync(Arg.Any<PromotePasswordResetDbCommand>(), Arg.Any<CancellationToken>())
                .Returns(call =>
                {
                    PromotePasswordResetDbCommand command = call.Arg<PromotePasswordResetDbCommand>();
                    return Task.FromResult<PromotePasswordResetResult?>(new PromotePasswordResetResult(
                        true,
                        PasswordResetService.CompletedCode,
                        command.AccountId,
                        command.NewSecurityStamp,
                        command.PromotedAt));
                });
        }

        public void ReadyReset(
            Guid resetId,
            Guid accountId,
            bool requiresTotp,
            string? method = null,
            bool requiresKeyCode = true,
            string? deliveryChannel = "email",
            string? keyCodeHash = "stored-hash")
        {
            Repo.GetPasswordResetRequestForFinalizeAsync(resetId, Arg.Any<CancellationToken>())
                .Returns(Task.FromResult<PasswordResetFinalizeRecord?>(new PasswordResetFinalizeRecord(
                    true,
                    PasswordResetService.ReadyCode,
                    resetId,
                    accountId,
                    method ?? PasswordResetDeliveryChannels.Email,
                    deliveryChannel,
                    keyCodeHash,
                    keyCodeHash is null ? null : 1,
                    requiresKeyCode,
                    requiresTotp,
                    SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(10)),
                    null,
                    null,
                    0,
                    5,
                    Guid.NewGuid())));
        }
    }
}
