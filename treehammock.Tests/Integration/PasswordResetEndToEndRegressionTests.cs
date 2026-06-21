using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Cache;
using treehammock.Models.PasswordReset;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Config;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Integration;

public class PasswordResetEndToEndRegressionTests
{
    private const string EmailIdentifier = "reader@example.com";
    private const string UsernameIdentifier = "reader";
    private const string SmsIdentifier = "+15555550101";
    private const string ResetCode = "49382710";
    private const string NewPassword = "new-password";

    [Theory]
    [InlineData(PasswordResetDeliveryChannels.Sms, false)]
    [InlineData(PasswordResetDeliveryChannels.Email, false)]
    [InlineData(PasswordResetDeliveryChannels.Sms, true)]
    [InlineData(PasswordResetDeliveryChannels.Email, true)]
    public async Task Password_reset_happy_path_completes_for_all_supported_delivery_channels(string method, bool authenticatorVerified)
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: authenticatorVerified);
        string identifier = method == PasswordResetDeliveryChannels.Sms ? SmsIdentifier : EmailIdentifier;

        PasswordResetRequestResult request = await harness.Service.RequestReset(
            new RequestPasswordResetCommand(identifier, method, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        request.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        request.ResetId.ShouldNotBe(Guid.Empty);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        reset.ResetId.ShouldBe(request.ResetId);
        reset.RequiresKeyCode.ShouldBeTrue();
        reset.RequiresTotp.ShouldBeFalse();
        if (reset.RequiresKeyCode)
        {
            PasswordResetDeliveryCommand delivery = harness.Delivery.LastDelivery.ShouldNotBeNull();
            delivery.ResetId.ShouldBe(reset.ResetId);
            delivery.KeyCode.ShouldBe(ResetCode);
            delivery.DeliveryChannel.ShouldBe(method.Contains("sms", StringComparison.Ordinal) ? "sms" : "email");
        }
        else
        {
            harness.Delivery.Deliveries.ShouldBeEmpty();
        }

        PasswordResetFinalizeResult finalized = await harness.CompleteVerifiedReset(reset, NewPassword);

        finalized.Code.ShouldBe(PasswordResetService.CompletedCode);
        finalized.StatusCode.ShouldBe(StatusCodes.Status200OK);
        reset.ConsumedAt.ShouldNotBeNull();
        reset.CancelledAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeTrue();
        account.CutOff.ShouldBeNull();
        account.ExistingSessionsInvalidated.ShouldBeTrue();
        account.SecurityStamp.ShouldNotBe(account.SecurityStampAtStart);
        harness.Repo.PromotionCount.ShouldBe(1);
    }


    [Theory]
    [MemberData(nameof(EmailBootstrapTwoFactorMatrixCases))]
    public async Task Email_bootstrap_verify_response_advertises_expected_reset_twofactor_matrix(
        bool emailVerified,
        bool smsVerified,
        bool authenticatorVerified,
        TwoFactorAuthConfiguration[] expectedConfigurations)
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: emailVerified,
            smsVerified: smsVerified,
            authenticatorVerified: authenticatorVerified);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, ResetCode, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        verified.StatusCode.ShouldBe(StatusCodes.Status200OK);
        verified.ResetAccessToken.ShouldNotBeNullOrWhiteSpace();
        verified.AvailableTwoFactorAuthConfigurations.ShouldBe(expectedConfigurations.ToList());
        verified.RequiresTwoFactor.ShouldBe(expectedConfigurations.Length > 0);
        verified.Code.ShouldBe(expectedConfigurations.Length > 0
            ? PasswordResetService.TwoFactorSelectionRequiredCode
            : PasswordResetService.TokenVerifiedCode);
        verified.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL);
        verified.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
    }

    public static TheoryData<bool, bool, bool, TwoFactorAuthConfiguration[]> EmailBootstrapTwoFactorMatrixCases()
    {
        return new TheoryData<bool, bool, bool, TwoFactorAuthConfiguration[]>
        {
            { false, false, false, [] },
            { true, false, false, [] },
            { false, true, false, [TwoFactorAuthConfiguration.SMS] },
            { false, false, true, [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { true, true, false, [TwoFactorAuthConfiguration.SMS] },
            { true, false, true, [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { false, true, true, [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP] },
            { true, true, true, [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP] }
        };
    }

    [Theory]
    [MemberData(nameof(SmsBootstrapTwoFactorMatrixCases))]
    public async Task Sms_bootstrap_verify_response_advertises_expected_reset_twofactor_matrix(
        bool emailVerified,
        bool smsVerified,
        bool authenticatorVerified,
        TwoFactorAuthConfiguration[] expectedConfigurations)
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: emailVerified,
            smsVerified: smsVerified,
            authenticatorVerified: authenticatorVerified);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Sms);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, ResetCode, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        verified.StatusCode.ShouldBe(StatusCodes.Status200OK);
        verified.ResetAccessToken.ShouldNotBeNullOrWhiteSpace();
        verified.AvailableTwoFactorAuthConfigurations.ShouldBe(expectedConfigurations.ToList());
        verified.RequiresTwoFactor.ShouldBe(expectedConfigurations.Length > 0);
        verified.Code.ShouldBe(expectedConfigurations.Length > 0
            ? PasswordResetService.TwoFactorSelectionRequiredCode
            : PasswordResetService.TokenVerifiedCode);
        verified.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS);
        verified.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
    }

    public static TheoryData<bool, bool, bool, TwoFactorAuthConfiguration[]> SmsBootstrapTwoFactorMatrixCases()
    {
        return new TheoryData<bool, bool, bool, TwoFactorAuthConfiguration[]>
        {
            { false, false, false, [] },
            { false, true, false, [] },
            { true, false, false, [TwoFactorAuthConfiguration.EMAIL] },
            { false, false, true, [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { true, true, false, [TwoFactorAuthConfiguration.EMAIL] },
            { false, true, true, [TwoFactorAuthConfiguration.AUTHENTICATOR_APP] },
            { true, false, true, [TwoFactorAuthConfiguration.EMAIL, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP] },
            { true, true, true, [TwoFactorAuthConfiguration.EMAIL, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP] }
        };
    }

    [Theory]
    [InlineData(PasswordResetDeliveryChannels.Email, TwoFactorAuthConfiguration.EMAIL)]
    [InlineData(PasswordResetDeliveryChannels.Email, TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP)]
    [InlineData(PasswordResetDeliveryChannels.Sms, TwoFactorAuthConfiguration.SMS)]
    [InlineData(PasswordResetDeliveryChannels.Sms, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP)]
    public async Task Bootstrap_delivery_factor_cannot_be_selected_as_the_only_reset_second_factor(
        string deliveryChannel,
        TwoFactorAuthConfiguration disallowedConfiguration)
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, deliveryChannel);

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, ResetCode, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        verified.AvailableTwoFactorAuthConfigurations.ShouldNotContain(disallowedConfiguration);

        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, disallowedConfiguration, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorConfigurationNotAvailableCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
    }

    [Fact]
    public async Task Password_reset_with_authenticator_requires_select_verify_finalize_sequence()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);

        verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        verified.ResetAccessToken.ShouldNotBeNullOrWhiteSpace();

        PasswordResetFinalizeResult finalizeBeforeSelection = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);
        finalizeBeforeSelection.Code.ShouldBe(PasswordResetService.TwoFactorNotCompleteCode);
        finalizeBeforeSelection.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        selected.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        harness.Delivery.Deliveries.Count.ShouldBe(1);

        PasswordResetTwoFactorVerifyResult proof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");

        proof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);
        proof.StatusCode.ShouldBe(StatusCodes.Status200OK);
        proof.CanChangePassword.ShouldBeTrue();

        PasswordResetFinalizeResult finalized = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);
        finalized.Code.ShouldBe(PasswordResetService.CompletedCode);
        finalized.StatusCode.ShouldBe(StatusCodes.Status200OK);
        account.PasswordPromoted.ShouldBeTrue();
        harness.Repo.PromotionCount.ShouldBe(1);
    }

    [Fact]
    public async Task Password_reset_email_bootstrap_select_sms_sends_challenge_and_promotes_after_sms_proof()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: false);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        verified.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.SMS]);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        selected.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
        PasswordResetDeliveryCommand smsChallenge = harness.Delivery.LastDelivery.ShouldNotBeNull();
        smsChallenge.ResetId.ShouldBe(reset.ResetId);
        smsChallenge.DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Sms);
        smsChallenge.Method.ShouldBe(PasswordResetDeliveryChannels.Sms);
        harness.Delivery.Deliveries.Count.ShouldBe(2);

        PasswordResetTwoFactorVerifyResult proof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.SMS_KEY,
            ResetCode);

        proof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);
        proof.CanChangePassword.ShouldBeTrue();

        PasswordResetFinalizeResult finalized = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);
        finalized.Code.ShouldBe(PasswordResetService.CompletedCode);
        finalized.StatusCode.ShouldBe(StatusCodes.Status200OK);
        account.PasswordPromoted.ShouldBeTrue();
        harness.Repo.PromotionCount.ShouldBe(1);
    }

    [Fact]
    public async Task Password_reset_sms_and_authenticator_rejects_finalize_after_only_sms_proof()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        selected.RemainingTwoFactorAuthMethods.ShouldBe([
            TwoFactorAuthMethod.SMS_KEY,
            TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        PasswordResetTwoFactorVerifyResult smsProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.SMS_KEY,
            ResetCode);

        smsProof.Code.ShouldBe(PasswordResetService.TwoFactorProofAcceptedNextProofRequiredCode);
        smsProof.StatusCode.ShouldBe(StatusCodes.Status200OK);
        smsProof.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        smsProof.CompletedTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY]);
        smsProof.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        smsProof.CanChangePassword.ShouldBeFalse();

        PasswordResetFinalizeResult finalizeAfterSmsOnly = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);
        finalizeAfterSmsOnly.Code.ShouldBe(PasswordResetService.TwoFactorNotCompleteCode);
        finalizeAfterSmsOnly.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);

        PasswordResetTwoFactorVerifyResult authenticatorProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");

        authenticatorProof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);
        authenticatorProof.CanChangePassword.ShouldBeTrue();

        PasswordResetFinalizeResult finalized = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);
        finalized.Code.ShouldBe(PasswordResetService.CompletedCode);
        finalized.StatusCode.ShouldBe(StatusCodes.Status200OK);
        account.PasswordPromoted.ShouldBeTrue();
        harness.Repo.PromotionCount.ShouldBe(1);
    }

    [Fact]
    public async Task Password_reset_combo_rejects_out_of_order_authenticator_proof()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        await harness.SelectResetTwoFactor(verified.ResetAccessToken!, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);

        PasswordResetTwoFactorVerifyResult outOfOrder = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");

        outOfOrder.Code.ShouldBe(PasswordResetService.TwoFactorMethodNotCurrentlyRequiredCode);
        outOfOrder.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        outOfOrder.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        outOfOrder.CanChangePassword.ShouldBeFalse();
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Password_reset_verify_twofactor_before_selection_is_rejected_without_promoting_password()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);

        PasswordResetTwoFactorVerifyResult proof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");

        proof.Code.ShouldBe(PasswordResetService.SessionExpiredCode);
        proof.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        proof.CanChangePassword.ShouldBeFalse();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Password_reset_rejects_configuration_not_in_verified_reset_options()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: false,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        verified.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorConfigurationNotAvailableCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        selected.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Request_returns_generic_accepted_for_unknown_account_without_creating_or_delivering_reset()
    {
        Harness harness = Harness.Create();

        PasswordResetRequestResult request = await harness.Service.RequestReset(
            new RequestPasswordResetCommand("missing@example.com", PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        request.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        request.ResetId.ShouldNotBe(Guid.Empty);
        harness.Repo.ResetCount.ShouldBe(0);
        harness.Delivery.Deliveries.ShouldBeEmpty();

        PasswordResetFinalizeResult decoyFinalize = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(request.ResetId, ResetCode, null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        decoyFinalize.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        decoyFinalize.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
    }

    [Fact]
    public async Task Request_creates_delivery_reset_without_requiring_client_to_choose_totp_strategy()
    {
        Harness harness = Harness.Create();
        harness.Repo.AddEligibleAccount(authenticatorVerified: false);

        PasswordResetRequestResult request = await harness.Service.RequestReset(
            new RequestPasswordResetCommand(EmailIdentifier, PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        request.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        request.ResetId.ShouldNotBe(Guid.Empty);
        harness.Repo.ResetCount.ShouldBe(1);
        PasswordResetDeliveryCommand delivery = harness.Delivery.LastDelivery.ShouldNotBeNull();
        delivery.DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Email);
        delivery.KeyCode.ShouldBe(ResetCode);
    }

    [Fact]
    public async Task Password_reset_verify_does_not_send_second_factor_challenge()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        harness.Delivery.Deliveries.Count.ShouldBe(1);
        harness.Delivery.Deliveries[0].DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);

        verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        harness.Delivery.Deliveries.Count.ShouldBe(1);
        harness.Delivery.Deliveries[0].ResetId.ShouldBe(reset.ResetId);
        harness.Delivery.Deliveries[0].DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Email);
    }

    [Fact]
    public async Task Password_reset_select_sms_sends_exactly_one_sms_challenge()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: false);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);

        harness.Delivery.Deliveries.Count.ShouldBe(1);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.SMS_KEY);
        harness.Delivery.Deliveries.Count.ShouldBe(2);
        harness.Delivery.Deliveries[1].ResetId.ShouldBe(reset.ResetId);
        harness.Delivery.Deliveries[1].DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Sms);
        harness.Delivery.Deliveries[1].Method.ShouldBe(PasswordResetDeliveryChannels.Sms);
        harness.Delivery.Deliveries[1].KeyCode.ShouldBe(ResetCode);
        harness.Delivery.Deliveries.Where(delivery => delivery.DeliveryChannel == PasswordResetDeliveryChannels.Sms).Count().ShouldBe(1);
    }

    [Fact]
    public async Task Password_reset_select_authenticator_sends_no_delivery_challenge()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);

        harness.Delivery.Deliveries.Count.ShouldBe(1);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);
        selected.CurrentRequiredMethod.ShouldBe(TwoFactorAuthMethod.AUTHENTICATOR_APP);
        selected.ChallengeExpiration.ShouldBeNull();
        harness.Delivery.Deliveries.Count.ShouldBe(1);
        harness.Delivery.Deliveries[0].DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Email);
    }

    [Fact]
    public async Task Password_reset_unavailable_selection_sends_no_delivery_challenge()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.EMAIL);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorConfigurationNotAvailableCode);
        selected.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        selected.CurrentRequiredMethod.ShouldBeNull();
        harness.Delivery.Deliveries.Count.ShouldBe(1);
        harness.Delivery.Deliveries[0].DeliveryChannel.ShouldBe(PasswordResetDeliveryChannels.Email);
    }

    [Fact]
    public async Task Delivery_failure_cancels_created_reset_artifact_without_changing_public_response()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount();
        harness.Delivery.NextResult = new PasswordResetDeliveryResult(false, PasswordResetDeliveryService.FailedCode);

        PasswordResetRequestResult request = await harness.Service.RequestReset(
            new RequestPasswordResetCommand(EmailIdentifier, PasswordResetDeliveryChannels.Email, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        request.Code.ShouldBe(PasswordResetService.RequestAcceptedCode);
        request.ResetId.ShouldNotBe(Guid.Empty);
        StoredReset reset = harness.Repo.ResetById(request.ResetId).ShouldNotBeNull();
        reset.AccountId.ShouldBe(account.AccountId);
        reset.CancelledAt.ShouldNotBeNull();
        harness.Repo.CancelCount.ShouldBe(1);

        PasswordResetFinalizeResult finalize = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(request.ResetId, ResetCode, null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        finalize.Code.ShouldBe(PasswordResetService.CancelledCode);
        finalize.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        account.PasswordPromoted.ShouldBeFalse();
    }

    [Fact]
    public async Task Wrong_key_code_records_attempts_and_attempt_exhaustion_cancels_reset()
    {
        Harness harness = Harness.Create(maxAttempts: 2);
        StoredAccount account = harness.Repo.AddEligibleAccount();
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetFinalizeResult first = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(reset.ResetId, "00000000", null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);
        PasswordResetFinalizeResult second = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(reset.ResetId, "11111111", null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        first.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        first.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        second.Code.ShouldBe(PasswordResetService.AttemptsExceededCode);
        second.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        reset.AttemptCount.ShouldBe(2);
        reset.CancelledAt.ShouldNotBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Wrong_reset_twofactor_totp_records_failed_attempt_without_promoting_password()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, ResetCode, "192.0.2.10", "unit-test"),
            CancellationToken.None);
        verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
        PasswordResetTwoFactorSelectResult selected = await harness.Service.SelectTwoFactorConfiguration(
            new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, TwoFactorAuthConfiguration.AUTHENTICATOR_APP, null, "192.0.2.10", "unit-test"),
            CancellationToken.None);
        selected.Code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);

        PasswordResetTwoFactorVerifyResult result = await harness.Service.VerifyTwoFactorProof(
            new VerifyPasswordResetTwoFactorCommand(verified.ResetAccessToken!, TwoFactorAuthMethod.AUTHENTICATOR_APP, "000000", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorChallengeInvalidCode);
        result.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        reset.AttemptCount.ShouldBe(1);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Direct_finalize_for_authenticator_account_requires_reset_twofactor_flow_and_does_not_count_as_bad_proof()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(reset.ResetId, ResetCode, null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.TwoFactorRequiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        reset.AttemptCount.ShouldBe(0);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
    }

    [Fact]
    public async Task Expired_reset_cannot_be_promoted()
    {
        Harness harness = Harness.Create(expirationMinutes: -1);
        StoredAccount account = harness.Repo.AddEligibleAccount();
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(reset.ResetId, ResetCode, null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.ExpiredCode);
        result.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Password_reset_token_expires_after_configured_two_minute_ttl()
    {
        Harness harness = Harness.Create(expirationMinutes: 2);
        StoredAccount account = harness.Repo.AddEligibleAccount(smsVerified: false);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        reset.ExpiresAt.ShouldBe(harness.Clock.Now.Plus(Duration.FromMinutes(2)));

        harness.Clock.Advance(Duration.FromSeconds(119));
        PasswordResetVerifyResult validJustBeforeExpiry = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, ResetCode, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        validJustBeforeExpiry.Code.ShouldBe(PasswordResetService.TokenVerifiedCode);
        validJustBeforeExpiry.StatusCode.ShouldBe(StatusCodes.Status200OK);

        harness.Clock.Advance(Duration.FromSeconds(2));
        PasswordResetVerifyResult expiredAfterTtl = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, ResetCode, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        expiredAfterTtl.Code.ShouldBe(PasswordResetService.ExpiredCode);
        expiredAfterTtl.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
    }

    [Fact]
    public async Task Password_reset_twofactor_session_expires_before_finalize()
    {
        Harness harness = Harness.Create(expirationMinutes: 2);
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        await harness.SelectResetTwoFactor(verified.ResetAccessToken!, TwoFactorAuthConfiguration.AUTHENTICATOR_APP);

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        PasswordResetSession session = (await harness.ResetSessionService.GetSession(resetAccessTokenHash)).ShouldNotBeNull();
        session.expiresAt = harness.Clock.Now.Plus(Duration.FromSeconds(30));

        harness.Clock.Advance(Duration.FromSeconds(31));

        PasswordResetTwoFactorVerifyResult staleProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");

        staleProof.Code.ShouldBe(PasswordResetService.SessionExpiredCode);
        staleProof.StatusCode.ShouldBe(StatusCodes.Status409Conflict);

        PasswordResetFinalizeResult staleFinalize = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);

        staleFinalize.Code.ShouldBe(PasswordResetService.TwoFactorNotCompleteCode);
        staleFinalize.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Password_reset_sms_challenge_code_expires_before_reset_session()
    {
        Harness harness = Harness.Create(expirationMinutes: 2);
        StoredAccount account = harness.Repo.AddEligibleAccount(smsVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS);

        selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        PasswordResetSession session = (await harness.ResetSessionService.GetSession(resetAccessTokenHash)).ShouldNotBeNull();
        session.expiresAt.ShouldBeGreaterThan(harness.Clock.Now);
        session.challengeExpiration = harness.Clock.Now.Minus(Duration.FromSeconds(1));

        PasswordResetTwoFactorVerifyResult expiredChallenge = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.SMS_KEY,
            ResetCode);

        expiredChallenge.Code.ShouldBe(PasswordResetService.SessionExpiredCode);
        expiredChallenge.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
    }

    [Fact]
    public async Task Consumed_reset_code_cannot_be_reused()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount();
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetFinalizeResult first = await harness.CompleteVerifiedReset(reset, NewPassword);
        PasswordResetFinalizeResult second = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(reset.ResetId, ResetCode, null, "another-password", "another-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        first.Code.ShouldBe(PasswordResetService.CompletedCode);
        second.Code.ShouldBe(PasswordResetService.ConsumedCode);
        second.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        harness.Repo.PromotionCount.ShouldBe(1);
    }

    [Fact]
    public async Task New_reset_request_cancels_prior_active_reset_id_for_same_account()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount();
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset firstReset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, UsernameIdentifier);
        StoredReset secondReset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        firstReset.ResetId.ShouldNotBe(secondReset.ResetId);
        firstReset.CancelledAt.ShouldNotBeNull();
        secondReset.CancelledAt.ShouldBeNull();

        PasswordResetFinalizeResult oldReset = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(firstReset.ResetId, ResetCode, null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);
        PasswordResetFinalizeResult newReset = await harness.CompleteVerifiedReset(secondReset, NewPassword);

        oldReset.Code.ShouldBe(PasswordResetService.CancelledCode);
        oldReset.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        newReset.Code.ShouldBe(PasswordResetService.CompletedCode);
        harness.Repo.PromotionCount.ShouldBe(1);
    }

    [Fact]
    public async Task Concurrent_password_reset_finalize_promotes_password_once()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        await harness.SelectResetTwoFactor(verified.ResetAccessToken!, TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        PasswordResetTwoFactorVerifyResult proof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");
        proof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);

        harness.Repo.ReleaseConcurrentPromotionsAfterEntrants(2);

        PasswordResetFinalizeResult[] results = await Task.WhenAll(
            harness.FinalizeWithAccessToken(verified.ResetAccessToken!),
            harness.FinalizeWithAccessToken(verified.ResetAccessToken!));

        results.Count(result => result.Code == PasswordResetService.CompletedCode).ShouldBe(1);
        results.Count(result => result.Code == PasswordResetService.ConsumedCode).ShouldBe(1);
        results.Count(result => result.StatusCode == StatusCodes.Status200OK).ShouldBe(1);
        results.Count(result => result.StatusCode == StatusCodes.Status409Conflict).ShouldBe(1);
        reset.ConsumedAt.ShouldNotBeNull();
        account.PasswordPromoted.ShouldBeTrue();
        harness.Repo.PromotionCount.ShouldBe(1);
    }

    [Fact]
    public async Task Concurrent_password_reset_requests_leave_one_active_reset()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount();

        harness.Repo.ReleaseConcurrentRequestCreationAfterEntrants(2);

        PasswordResetRequestResult[] requests = await Task.WhenAll(
            harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier),
            harness.RequestReset(PasswordResetDeliveryChannels.Email, UsernameIdentifier));

        requests.All(request => request.Code == PasswordResetService.RequestAcceptedCode).ShouldBeTrue();
        requests.Select(request => request.ResetId).Distinct().Count().ShouldBe(2);
        harness.Repo.ActiveResetCountFor(account.AccountId).ShouldBe(1);
        harness.Repo.CancelledResetCountFor(account.AccountId).ShouldBe(1);

        StoredReset activeReset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
        requests.Select(request => request.ResetId).ShouldContain(activeReset.ResetId);

        PasswordResetRequestResult cancelledRequest = requests.Single(request => request.ResetId != activeReset.ResetId);
        PasswordResetFinalizeResult cancelledFinalize = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(cancelledRequest.ResetId, ResetCode, null, NewPassword, NewPassword, "192.0.2.10", "unit-test"),
            CancellationToken.None);

        cancelledFinalize.Code.ShouldBe(PasswordResetService.CancelledCode);
        cancelledFinalize.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Method_removal_racing_reset_twofactor_verify_does_not_promote_password()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeTrue();

        Task<PasswordResetTwoFactorVerifyResult> proofTask = harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.SMS_KEY,
            ResetCode);
        Task removalTask = harness.SimulateTwoFactorMethodRemoval(
            account,
            TwoFactorAuthMethod.SMS_KEY,
            verified.ResetAccessToken!);

        PasswordResetTwoFactorVerifyResult proof = await proofTask;
        await removalTask;

        new[] { StatusCodes.Status200OK, StatusCodes.Status409Conflict }.ShouldContain(proof.StatusCode);
        new[]
        {
            PasswordResetService.TwoFactorProofAcceptedNextProofRequiredCode,
            PasswordResetService.SessionExpiredCode
        }.ShouldContain(proof.Code);
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeFalse();

        PasswordResetFinalizeResult finalize = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);
        finalize.Code.ShouldBe(PasswordResetService.TwoFactorNotCompleteCode);
        finalize.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Password_mismatch_fails_before_reset_lookup_or_promotion()
    {
        Harness harness = Harness.Create();

        PasswordResetFinalizeResult result = await harness.Service.FinalizeReset(
            new FinalizePasswordResetCommand(Guid.NewGuid(), ResetCode, null, NewPassword, "different-password", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        result.Code.ShouldBe(PasswordResetService.ValidationFailedCode);
        result.StatusCode.ShouldBe(StatusCodes.Status400BadRequest);
        harness.Repo.FinalizeLookupCount.ShouldBe(0);
        harness.Repo.PromotionCount.ShouldBe(0);
    }

    [Fact]
    public async Task Removing_authenticator_revokes_pending_reset_session_and_future_reset_keeps_sms_only()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        selected.StatusCode.ShouldBe(StatusCodes.Status200OK);
        selected.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeTrue();

        await harness.SimulateTwoFactorMethodRemoval(account, TwoFactorAuthMethod.AUTHENTICATOR_APP, verified.ResetAccessToken!);

        account.AuthenticatorVerified.ShouldBeFalse();
        account.SmsVerified.ShouldBeTrue();
        account.EmailVerified.ShouldBeTrue();
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeFalse();

        PasswordResetTwoFactorVerifyResult staleProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.SMS_KEY,
            ResetCode);
        staleProof.Code.ShouldBe(PasswordResetService.SessionExpiredCode);
        staleProof.StatusCode.ShouldBe(StatusCodes.Status409Conflict);

        PasswordResetFinalizeResult staleFinalize = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);
        staleFinalize.Code.ShouldBe(PasswordResetService.TwoFactorNotCompleteCode);
        staleFinalize.StatusCode.ShouldBe(StatusCodes.Status409Conflict);
        account.PasswordPromoted.ShouldBeFalse();

        PasswordResetVerifyResult future = await harness.RequestAndVerifyFutureReset(account, PasswordResetDeliveryChannels.Email, EmailIdentifier);
        future.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.SMS]);
        future.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        future.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        future.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
    }

    [Fact]
    public async Task Removing_sms_revokes_pending_reset_session_and_future_reset_keeps_authenticator_available()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Email, EmailIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        await harness.SelectResetTwoFactor(verified.ResetAccessToken!, TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeTrue();

        await harness.SimulateTwoFactorMethodRemoval(account, TwoFactorAuthMethod.SMS_KEY, verified.ResetAccessToken!);

        account.SmsVerified.ShouldBeFalse();
        account.AuthenticatorVerified.ShouldBeTrue();
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeFalse();

        PasswordResetTwoFactorVerifyResult staleProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.SMS_KEY,
            ResetCode);
        staleProof.Code.ShouldBe(PasswordResetService.SessionExpiredCode);
        staleProof.StatusCode.ShouldBe(StatusCodes.Status409Conflict);

        PasswordResetVerifyResult future = await harness.RequestAndVerifyFutureReset(account, PasswordResetDeliveryChannels.Email, EmailIdentifier);
        future.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        future.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS);
        future.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
    }

    [Fact]
    public async Task Removing_email_revokes_pending_reset_session_and_future_sms_bootstrap_keeps_authenticator_available()
    {
        Harness harness = Harness.Create();
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        await harness.RequestReset(PasswordResetDeliveryChannels.Sms, SmsIdentifier);
        StoredReset reset = harness.Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.EMAIL);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
        await harness.SelectResetTwoFactor(verified.ResetAccessToken!, TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);

        string resetAccessTokenHash = AccessTokenHashUtility.Hash(verified.ResetAccessToken!);
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeTrue();

        await harness.SimulateTwoFactorMethodRemoval(account, TwoFactorAuthMethod.EMAIL, verified.ResetAccessToken!);

        account.EmailVerified.ShouldBeFalse();
        account.AuthenticatorVerified.ShouldBeTrue();
        harness.ResetSessionService.HasSession(resetAccessTokenHash).ShouldBeFalse();

        PasswordResetTwoFactorVerifyResult staleProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.EMAIL,
            ResetCode);
        staleProof.Code.ShouldBe(PasswordResetService.SessionExpiredCode);
        staleProof.StatusCode.ShouldBe(StatusCodes.Status409Conflict);

        PasswordResetVerifyResult future = await harness.RequestAndVerifyFutureReset(account, PasswordResetDeliveryChannels.Sms, SmsIdentifier);
        future.AvailableTwoFactorAuthConfigurations.ShouldBe([TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);
        future.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL);
        future.AvailableTwoFactorAuthConfigurations.ShouldNotContain(TwoFactorAuthConfiguration.EMAIL_AND_AUTHENTICATOR_APP);
    }


    [Fact]
    public async Task Password_reset_combo_flow_does_not_exhaust_shared_attempt_quota()
    {
        RecordingAbuseCounterStore abuseCounters = new();
        Harness harness = Harness.Create(
            abuseCounterStore: abuseCounters,
            passwordResetAbusePolicySettings: SplitAbuseThresholds(tokenAttempts: 1, proofAttempts: 2, finalizeAttempts: 1));
        StoredAccount account = harness.Repo.AddEligibleAccount(
            emailVerified: true,
            smsVerified: true,
            authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        verified.AvailableTwoFactorAuthConfigurations.ShouldContain(TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);

        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.SMS_AND_AUTHENTICATOR_APP);
        selected.Code.ShouldBe(PasswordResetService.TwoFactorChallengeSentCode);
        selected.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        PasswordResetTwoFactorVerifyResult smsProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.SMS_KEY,
            ResetCode);
        smsProof.Code.ShouldBe(PasswordResetService.TwoFactorProofAcceptedNextProofRequiredCode);
        smsProof.RemainingTwoFactorAuthMethods.ShouldBe([TwoFactorAuthMethod.AUTHENTICATOR_APP]);

        PasswordResetTwoFactorVerifyResult authenticatorProof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");
        authenticatorProof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);
        authenticatorProof.CanChangePassword.ShouldBeTrue();

        PasswordResetFinalizeResult finalized = await harness.FinalizeWithAccessToken(verified.ResetAccessToken!);

        finalized.Code.ShouldBe(PasswordResetService.CompletedCode);
        finalized.StatusCode.ShouldBe(StatusCodes.Status200OK);
        account.PasswordPromoted.ShouldBeTrue();
        harness.Repo.PromotionCount.ShouldBe(1);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTokenVerification).ShouldBe(1);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTwoFactorProof).ShouldBe(2);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetFinalize).ShouldBe(1);
    }

    [Fact]
    public async Task Password_reset_select_does_not_increment_reset_scoped_abuse_counters()
    {
        RecordingAbuseCounterStore abuseCounters = new();
        Harness harness = Harness.Create(
            abuseCounterStore: abuseCounters,
            passwordResetAbusePolicySettings: SplitAbuseThresholds(tokenAttempts: 5, proofAttempts: 1, finalizeAttempts: 1));
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTokenVerification).ShouldBe(1);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTwoFactorProof).ShouldBe(0);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetFinalize).ShouldBe(0);

        for (int i = 0; i < 3; i++)
        {
            PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
                verified.ResetAccessToken!,
                TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
            selected.Code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);
        }

        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTokenVerification).ShouldBe(1);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTwoFactorProof).ShouldBe(0);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetFinalize).ShouldBe(0);
        reset.AttemptCount.ShouldBe(0);
        account.PasswordPromoted.ShouldBeFalse();
    }

    [Fact]
    public async Task Wrong_reset_key_code_throttles_token_verification_only()
    {
        RecordingAbuseCounterStore abuseCounters = new();
        Harness harness = Harness.Create(
            abuseCounterStore: abuseCounters,
            passwordResetAbusePolicySettings: SplitAbuseThresholds(tokenAttempts: 2, proofAttempts: 1, finalizeAttempts: 1));
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult first = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, "00000000", "192.0.2.10", "unit-test"),
            CancellationToken.None);
        PasswordResetVerifyResult second = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, "11111111", "192.0.2.10", "unit-test"),
            CancellationToken.None);
        PasswordResetVerifyResult third = await harness.Service.VerifyResetToken(
            new VerifyPasswordResetTokenCommand(reset.ResetId, "22222222", "192.0.2.10", "unit-test"),
            CancellationToken.None);

        first.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        first.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        second.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        second.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        third.Code.ShouldBe(PasswordResetService.AttemptsExceededCode);
        third.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        reset.AttemptCount.ShouldBe(2);
        reset.CancelledAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTokenVerification).ShouldBe(3);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTwoFactorProof).ShouldBe(0);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetFinalize).ShouldBe(0);
    }

    [Fact]
    public async Task Wrong_reset_totp_throttles_twofactor_proof_only()
    {
        RecordingAbuseCounterStore abuseCounters = new();
        Harness harness = Harness.Create(
            abuseCounterStore: abuseCounters,
            passwordResetAbusePolicySettings: SplitAbuseThresholds(tokenAttempts: 5, proofAttempts: 2, finalizeAttempts: 1));
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        PasswordResetTwoFactorSelectResult selected = await harness.SelectResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        selected.Code.ShouldBe(PasswordResetService.TwoFactorAuthenticatorCodeRequiredCode);

        PasswordResetTwoFactorVerifyResult first = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "000000");
        PasswordResetTwoFactorVerifyResult second = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "111111");
        PasswordResetTwoFactorVerifyResult third = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "222222");

        first.Code.ShouldBe(PasswordResetService.TwoFactorChallengeInvalidCode);
        first.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        second.Code.ShouldBe(PasswordResetService.TwoFactorChallengeInvalidCode);
        second.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        third.Code.ShouldBe(PasswordResetService.AttemptsExceededCode);
        third.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        reset.AttemptCount.ShouldBe(2);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTokenVerification).ShouldBe(1);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTwoFactorProof).ShouldBe(3);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetFinalize).ShouldBe(0);
    }

    [Fact]
    public async Task Wrong_finalize_throttles_finalize_only_after_twofactor_completion()
    {
        RecordingAbuseCounterStore abuseCounters = new();
        Harness harness = Harness.Create(
            abuseCounterStore: abuseCounters,
            passwordResetAbusePolicySettings: SplitAbuseThresholds(tokenAttempts: 5, proofAttempts: 5, finalizeAttempts: 2));
        StoredAccount account = harness.Repo.AddEligibleAccount(authenticatorVerified: true);
        StoredReset reset = harness.SeedVerifiedReset(account, PasswordResetDeliveryChannels.Email);

        PasswordResetVerifyResult verified = await harness.VerifyReset(reset);
        await harness.SelectResetTwoFactor(verified.ResetAccessToken!, TwoFactorAuthConfiguration.AUTHENTICATOR_APP);
        PasswordResetTwoFactorVerifyResult proof = await harness.VerifyResetTwoFactor(
            verified.ResetAccessToken!,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "123456");
        proof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);
        int proofCounterBeforeFinalize = abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTwoFactorProof);
        string badResetAccessToken = TamperResetAccessTokenSignature(verified.ResetAccessToken!);

        PasswordResetFinalizeResult first = await harness.FinalizeWithAccessToken(badResetAccessToken);
        PasswordResetFinalizeResult second = await harness.FinalizeWithAccessToken(badResetAccessToken);
        PasswordResetFinalizeResult third = await harness.FinalizeWithAccessToken(badResetAccessToken);

        first.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        first.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        second.Code.ShouldBe(PasswordResetService.InvalidProofCode);
        second.StatusCode.ShouldBe(StatusCodes.Status401Unauthorized);
        third.Code.ShouldBe(PasswordResetService.AttemptsExceededCode);
        third.StatusCode.ShouldBe(StatusCodes.Status429TooManyRequests);
        reset.ConsumedAt.ShouldBeNull();
        account.PasswordPromoted.ShouldBeFalse();
        harness.Repo.PromotionCount.ShouldBe(0);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTokenVerification).ShouldBe(1);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetTwoFactorProof).ShouldBe(proofCounterBeforeFinalize);
        abuseCounters.IncrementCalls(AbuseFeature.PasswordResetFinalize).ShouldBe(3);
    }

    private static PasswordResetAbusePolicySettings SplitAbuseThresholds(
        int tokenAttempts,
        int proofAttempts,
        int finalizeAttempts)
    {
        return new PasswordResetAbusePolicySettings
        {
            Enabled = true,
            MaxRequestsPerAccountPerHour = 100,
            MaxRequestsPerIdentifierPerHour = 100,
            MaxRequestsPerIpPerHour = 100,
            MaxTokenVerificationAttemptsPerResetId = tokenAttempts,
            TokenVerificationAttemptWindowSeconds = 60,
            MaxTwoFactorProofAttemptsPerResetId = proofAttempts,
            TwoFactorProofAttemptWindowSeconds = 60,
            MaxFinalizeAttemptsPerResetId = finalizeAttempts,
            FinalizeAttemptWindowSeconds = 60,
            CooldownSecondsAfterExhaustion = 0
        };
    }

    private static string TamperResetAccessTokenSignature(string resetAccessToken)
    {
        string[] parts = resetAccessToken.Split('.', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        parts.Length.ShouldBe(2);
        string signature = parts[1];
        char replacement = signature[0] == 'a' ? 'b' : 'a';
        return $"{parts[0]}.{replacement}{signature[1..]}";
    }

    private sealed class Harness
    {
        private Harness(
            PasswordResetService service,
            InMemoryPasswordResetRepo repo,
            CapturingPasswordResetDeliveryService delivery,
            InMemoryPasswordResetSessionService resetSessionService,
            PasswordResetCodeHasher codeHasher,
            RecordingAbuseCounterStore abuseCounters,
            TestClock clock)
        {
            Service = service;
            Repo = repo;
            Delivery = delivery;
            ResetSessionService = resetSessionService;
            CodeHasher = codeHasher;
            AbuseCounters = abuseCounters;
            Clock = clock;
        }

        public PasswordResetService Service { get; }

        public InMemoryPasswordResetRepo Repo { get; }

        public CapturingPasswordResetDeliveryService Delivery { get; }

        public InMemoryPasswordResetSessionService ResetSessionService { get; }

        public PasswordResetCodeHasher CodeHasher { get; }

        public RecordingAbuseCounterStore AbuseCounters { get; }

        public TestClock Clock { get; }

        public static Harness Create(
            int maxAttempts = 5,
            int expirationMinutes = 2,
            RecordingAbuseCounterStore? abuseCounterStore = null,
            PasswordResetAbusePolicySettings? passwordResetAbusePolicySettings = null)
        {
            PasswordResetSettings settings = new()
            {
                CodeLength = 8,
                CodeHashPepper = "unit-test-password-reset-pepper",
                ExpirationMinutes = expirationMinutes,
                MaxAttempts = maxAttempts,
                RequestCooldownSeconds = 60,
                DailyRequestLimitPerAccount = 50,
                DailyRequestLimitPerDestination = 50,
                DailyRequestLimitPerIp = 50,
                DailyRequestWindowHours = 24,
                RateLimitBlockMinutes = 30,
                CaptchaChallengeEnabled = false,
                CaptchaChallengeAfterRequests = 3
            };
            var hasher = new PasswordResetCodeHasher(Options.Create(settings));
            var clock = new TestClock(Instant.FromUtc(2026, 1, 1, 0, 0));
            var repo = new InMemoryPasswordResetRepo(clock);
            var delivery = new CapturingPasswordResetDeliveryService();
            var generator = new FixedPasswordResetCodeGenerator(ResetCode);
            var keyFactory = new PasswordResetRateLimitKeyFactory(Options.Create(settings));
            var abusePolicy = new PasswordResetAbusePolicy(Options.Create(settings));
            var abuseCounterKeyFactory = new PasswordResetAbuseCounterKeyFactory(Options.Create(settings));
            AbuseControlSettings abuseControlSettings = new()
            {
                PasswordReset = passwordResetAbusePolicySettings ?? new PasswordResetAbusePolicySettings { Enabled = false }
            };
            RecordingAbuseCounterStore counters = abuseCounterStore ?? new RecordingAbuseCounterStore();
            var totpVerifier = new FixedPasswordResetTotpVerifier("123456");
            var passwordMaterialFactory = new FixedPasswordMaterialFactory();
            var resetSessionService = new InMemoryPasswordResetSessionService();

            var service = new PasswordResetService(
                repo,
                generator,
                hasher,
                keyFactory,
                abusePolicy,
                abuseCounterKeyFactory,
                counters,
                Options.Create(abuseControlSettings),
                delivery,
                totpVerifier,
                passwordMaterialFactory,
                Options.Create(settings),
                Options.Create(new RegistrationSettings
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
                }),
                NullLogger<PasswordResetService>.Instance,
                clock,
                resetSessionService);

            return new Harness(service, repo, delivery, resetSessionService, hasher, counters, clock);
        }

        public StoredReset SeedVerifiedReset(StoredAccount account, string deliveryChannel)
        {
            Guid resetId = Guid.NewGuid();
            return Repo.AddResetArtifact(
                account,
                resetId,
                deliveryChannel,
                CodeHasher.HashCode(resetId, ResetCode),
                CodeHasher.HashVersion);
        }

        public async Task<PasswordResetVerifyResult> VerifyReset(StoredReset reset)
        {
            PasswordResetVerifyResult verified = await Service.VerifyResetToken(
                new VerifyPasswordResetTokenCommand(reset.ResetId, ResetCode, "192.0.2.10", "unit-test"),
                CancellationToken.None);

            verified.StatusCode.ShouldBe(StatusCodes.Status200OK);
            verified.ResetAccessToken.ShouldNotBeNullOrWhiteSpace();
            return verified;
        }

        public Task<PasswordResetTwoFactorSelectResult> SelectResetTwoFactor(
            string resetAccessToken,
            TwoFactorAuthConfiguration configuration)
        {
            return Service.SelectTwoFactorConfiguration(
                new SelectPasswordResetTwoFactorConfigurationCommand(resetAccessToken, configuration, null, "192.0.2.10", "unit-test"),
                CancellationToken.None);
        }

        public Task<PasswordResetTwoFactorVerifyResult> VerifyResetTwoFactor(
            string resetAccessToken,
            TwoFactorAuthMethod method,
            string code)
        {
            return Service.VerifyTwoFactorProof(
                new VerifyPasswordResetTwoFactorCommand(resetAccessToken, method, code, "192.0.2.10", "unit-test"),
                CancellationToken.None);
        }

        public Task<PasswordResetFinalizeResult> FinalizeWithAccessToken(
            string resetAccessToken,
            string password = NewPassword)
        {
            return Service.FinalizeReset(
                new FinalizePasswordResetCommand(Guid.Empty, null, null, password, password, "192.0.2.10", "unit-test", resetAccessToken),
                CancellationToken.None);
        }

        public async Task<PasswordResetFinalizeResult> CompleteVerifiedReset(StoredReset reset, string password)
        {
            PasswordResetVerifyResult verified = await VerifyReset(reset);

            if (verified.RequiresTwoFactor)
            {
                await CompleteRequiredResetTwoFactor(verified);
            }
            else
            {
                verified.Code.ShouldBe(PasswordResetService.TokenVerifiedCode);
            }

            return await FinalizeWithAccessToken(verified.ResetAccessToken!, password);
        }

        private async Task CompleteRequiredResetTwoFactor(PasswordResetVerifyResult verified)
        {
            verified.Code.ShouldBe(PasswordResetService.TwoFactorSelectionRequiredCode);
            verified.AvailableTwoFactorAuthConfigurations.ShouldNotBeEmpty();

            TwoFactorAuthConfiguration selectedConfiguration = ChooseResetTwoFactorConfiguration(verified.AvailableTwoFactorAuthConfigurations);
            PasswordResetTwoFactorSelectResult selected = await Service.SelectTwoFactorConfiguration(
                new SelectPasswordResetTwoFactorConfigurationCommand(verified.ResetAccessToken!, selectedConfiguration, null, "192.0.2.10", "unit-test"),
                CancellationToken.None);

            selected.StatusCode.ShouldBe(StatusCodes.Status200OK);
            List<TwoFactorAuthMethod> remaining = selected.RemainingTwoFactorAuthMethods.ToList();
            remaining.ShouldNotBeEmpty();

            PasswordResetTwoFactorVerifyResult proof = null!;
            while (remaining.Count > 0)
            {
                TwoFactorAuthMethod method = remaining[0];
                string code = method == TwoFactorAuthMethod.AUTHENTICATOR_APP ? "123456" : ResetCode;
                proof = await Service.VerifyTwoFactorProof(
                    new VerifyPasswordResetTwoFactorCommand(verified.ResetAccessToken!, method, code, "192.0.2.10", "unit-test"),
                    CancellationToken.None);

                proof.StatusCode.ShouldBe(StatusCodes.Status200OK);
                remaining = proof.RemainingTwoFactorAuthMethods.ToList();
            }

            proof.Code.ShouldBe(PasswordResetService.TwoFactorCompleteCode);
            proof.CanChangePassword.ShouldBeTrue();
        }

        private static TwoFactorAuthConfiguration ChooseResetTwoFactorConfiguration(IReadOnlyCollection<TwoFactorAuthConfiguration> configurations)
        {
            if (configurations.Contains(TwoFactorAuthConfiguration.AUTHENTICATOR_APP))
            {
                return TwoFactorAuthConfiguration.AUTHENTICATOR_APP;
            }

            if (configurations.Contains(TwoFactorAuthConfiguration.SMS))
            {
                return TwoFactorAuthConfiguration.SMS;
            }

            if (configurations.Contains(TwoFactorAuthConfiguration.EMAIL))
            {
                return TwoFactorAuthConfiguration.EMAIL;
            }

            return configurations.First();
        }

        public Task<PasswordResetRequestResult> RequestReset(string method, string identifier)
        {
            return Service.RequestReset(
                new RequestPasswordResetCommand(identifier, method, "192.0.2.10", "unit-test"),
                CancellationToken.None);
        }

        public async Task<PasswordResetVerifyResult> RequestAndVerifyFutureReset(
            StoredAccount account,
            string deliveryChannel,
            string identifier)
        {
            await RequestReset(deliveryChannel, identifier);
            StoredReset reset = Repo.ActiveResetFor(account.AccountId).ShouldNotBeNull();
            return await VerifyReset(reset);
        }

        public async Task SimulateTwoFactorMethodRemoval(
            StoredAccount account,
            TwoFactorAuthMethod removedMethod,
            string resetAccessToken)
        {
            switch (removedMethod)
            {
                case TwoFactorAuthMethod.EMAIL:
                    account.EmailVerified = false;
                    break;
                case TwoFactorAuthMethod.SMS_KEY:
                    account.SmsVerified = false;
                    break;
                case TwoFactorAuthMethod.AUTHENTICATOR_APP:
                    account.AuthenticatorVerified = false;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(removedMethod), removedMethod, "Only configured 2FA methods can be removed.");
            }

            await ResetSessionService.RevokeSession(AccessTokenHashUtility.Hash(resetAccessToken));
        }
    }

    private sealed class TestClock : IClock
    {
        public TestClock(Instant now)
        {
            Now = now;
        }

        public Instant Now { get; private set; }

        public Instant GetCurrentInstant() => Now;

        public void Advance(Duration duration)
        {
            Now = Now.Plus(duration);
        }
    }

    private sealed class InMemoryPasswordResetSessionService : IPasswordResetSessionService
    {
        private readonly Dictionary<string, PasswordResetSession> _sessions = new();

        public bool HasSession(string resetAccessTokenHash)
        {
            return _sessions.ContainsKey(resetAccessTokenHash);
        }

        public Task<PasswordResetSession?> GetSession(string resetAccessTokenHash)
        {
            _sessions.TryGetValue(resetAccessTokenHash, out PasswordResetSession? session);
            return Task.FromResult(session);
        }

        public Task<bool?> SetSession(
            string resetAccessTokenHash,
            PasswordResetSession session,
            TimeSpan expire,
            StackExchange.Redis.CommandFlags flags = StackExchange.Redis.CommandFlags.PreferMaster)
        {
            _sessions[resetAccessTokenHash] = session;
            return Task.FromResult<bool?>(true);
        }

        public Task<bool> RevokeSession(string resetAccessTokenHash)
        {
            _sessions.Remove(resetAccessTokenHash);
            return Task.FromResult(true);
        }
    }

    private sealed class RecordingAbuseCounterStore : IAbuseCounterStore
    {
        private readonly Dictionary<string, int> _activeCounts = new();
        private readonly List<AbuseCounterKey> _increments = new();
        private readonly List<AbuseCounterKey> _resets = new();

        public int IncrementCalls(AbuseFeature feature)
        {
            return _increments.Count(key => key.Feature == feature);
        }

        public int ResetCalls(AbuseFeature feature)
        {
            return _resets.Count(key => key.Feature == feature);
        }

        public Task<CounterDecision> IncrementAsync(
            AbuseCounterKey key,
            AbuseCounterLimit limit,
            CancellationToken cancellationToken = default)
        {
            _increments.Add(key);
            _activeCounts.TryGetValue(key.Value, out int currentCount);
            int nextCount = currentCount + 1;
            _activeCounts[key.Value] = nextCount;

            if (nextCount <= limit.MaxAttempts)
            {
                return Task.FromResult(new CounterDecision(
                    true,
                    nextCount,
                    limit.MaxAttempts,
                    limit.Window,
                    null,
                    null));
            }

            return Task.FromResult(new CounterDecision(
                false,
                nextCount,
                limit.MaxAttempts,
                limit.Window,
                limit.Window,
                AbuseReasonCodes.CounterLimitExceeded));
        }

        public Task ResetAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            _resets.Add(key);
            _activeCounts.Remove(key.Value);
            return Task.CompletedTask;
        }

        public Task<CooldownDecision> GetCooldownAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CooldownDecision(false, null, null));
        }
    }

    private sealed class InMemoryPasswordResetRepo : IPasswordResetRepo
    {
        private readonly IClock _clock;
        private readonly List<StoredAccount> _accounts = new();
        private readonly Dictionary<Guid, StoredReset> _resets = new();
        private readonly object _sync = new();
        private TaskCompletionSource<bool>? _promotionGate;
        private int _promotionGateEntrants;
        private int _promotionGateTarget;
        private TaskCompletionSource<bool>? _createRequestGate;
        private int _createRequestGateEntrants;
        private int _createRequestGateTarget;

        public InMemoryPasswordResetRepo(IClock clock)
        {
            _clock = clock;
        }

        public int ResetCount => _resets.Count;

        public int CancelCount { get; private set; }

        public int PromotionCount { get; private set; }

        public int FinalizeLookupCount { get; private set; }

        public StoredAccount AddEligibleAccount(bool emailVerified = true, bool smsVerified = true, bool authenticatorVerified = false)
        {
            StoredAccount account = new(
                Guid.NewGuid(),
                EmailIdentifier,
                UsernameIdentifier,
                "5555550101",
                "+1",
                Guid.NewGuid(),
                emailVerified,
                smsVerified,
                authenticatorVerified);
            _accounts.Add(account);
            return account;
        }

        public StoredReset? ActiveResetFor(Guid accountId)
        {
            lock (_sync)
            {
                return _resets.Values
                    .Where(reset => reset.AccountId == accountId && reset.ConsumedAt is null && reset.CancelledAt is null)
                    .OrderByDescending(reset => reset.CreatedAt)
                    .FirstOrDefault();
            }
        }

        public int ActiveResetCountFor(Guid accountId)
        {
            lock (_sync)
            {
                return _resets.Values.Count(reset => reset.AccountId == accountId && reset.ConsumedAt is null && reset.CancelledAt is null);
            }
        }

        public int CancelledResetCountFor(Guid accountId)
        {
            lock (_sync)
            {
                return _resets.Values.Count(reset => reset.AccountId == accountId && reset.CancelledAt is not null);
            }
        }

        public void ReleaseConcurrentPromotionsAfterEntrants(int entrants)
        {
            _promotionGateTarget = entrants;
            _promotionGateEntrants = 0;
            _promotionGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        public void ReleaseConcurrentRequestCreationAfterEntrants(int entrants)
        {
            _createRequestGateTarget = entrants;
            _createRequestGateEntrants = 0;
            _createRequestGate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        public StoredReset? ResetById(Guid resetId)
        {
            lock (_sync)
            {
                _resets.TryGetValue(resetId, out StoredReset? reset);
                return reset;
            }
        }

        public StoredReset AddResetArtifact(
            StoredAccount account,
            Guid resetId,
            string deliveryChannel,
            string keyCodeHash,
            int keyCodeHashVersion)
        {
            Instant now = _clock.GetCurrentInstant();
            StoredReset reset = new(
                resetId,
                account.AccountId,
                deliveryChannel,
                deliveryChannel,
                keyCodeHash,
                keyCodeHashVersion,
                requiresKeyCode: true,
                requiresTotp: false,
                createdAt: now,
                expiresAt: now.Plus(Duration.FromMinutes(2)),
                maxAttempts: 5,
                accountSecurityStampAtRequest: account.SecurityStamp);
            lock (_sync)
            {
                _resets[resetId] = reset;
            }

            return reset;
        }

        private async Task AwaitPromotionRaceGate()
        {
            TaskCompletionSource<bool>? gate = _promotionGate;
            if (gate is null)
            {
                return;
            }

            if (Interlocked.Increment(ref _promotionGateEntrants) >= _promotionGateTarget)
            {
                gate.TrySetResult(true);
            }

            await gate.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }

        private async Task AwaitCreateRequestRaceGate()
        {
            TaskCompletionSource<bool>? gate = _createRequestGate;
            if (gate is null)
            {
                return;
            }

            if (Interlocked.Increment(ref _createRequestGateEntrants) >= _createRequestGateTarget)
            {
                gate.TrySetResult(true);
            }

            await gate.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }

        public Task<PasswordResetAccountLookupResult?> LookupPasswordResetAccountAsync(
            string identifier,
            Instant now,
            CancellationToken cancellationToken)
        {
            StoredAccount? account = _accounts.FirstOrDefault(candidate => candidate.Matches(identifier));
            if (account is null)
            {
                return Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                    false,
                    PasswordResetService.AccountNotFoundCode,
                    null,
                    null,
                    null,
                    null,
                    null,
                    false,
                    false,
                    false));
            }

            return Task.FromResult<PasswordResetAccountLookupResult?>(new PasswordResetAccountLookupResult(
                true,
                "PASSWORD_RESET_ACCOUNT_FOUND",
                account.AccountId,
                account.EmailAddress,
                account.PhoneNumber,
                account.PhoneCountryCode,
                account.SecurityStamp,
                account.EmailVerified,
                account.SmsVerified,
                account.AuthenticatorVerified));
        }

        public async Task<CreatePasswordResetRequestDbResult?> CreatePasswordResetRequestAsync(
            CreatePasswordResetRequestDbCommand command,
            CancellationToken cancellationToken)
        {
            await AwaitCreateRequestRaceGate();

            lock (_sync)
            {
                Instant now = _clock.GetCurrentInstant();
                foreach (StoredReset reset in _resets.Values.Where(reset => reset.AccountId == command.AccountId && reset.ConsumedAt is null && reset.CancelledAt is null))
                {
                    reset.CancelledAt = now;
                }

                StoredReset created = new(
                    command.PasswordResetRequestId,
                    command.AccountId,
                    command.Method,
                    command.DeliveryChannel,
                    command.KeyCodeHash,
                    command.KeyCodeHashVersion,
                    command.RequiresKeyCode,
                    command.RequiresTotp,
                    now,
                    command.ExpiresAt,
                    command.MaxAttempts,
                    command.AccountSecurityStampAtRequest);
                _resets[created.ResetId] = created;

                return new CreatePasswordResetRequestDbResult(
                    true,
                    "PASSWORD_RESET_REQUEST_CREATED",
                    created.ResetId,
                    created.AccountId,
                    created.ExpiresAt);
            }
        }

        public Task<PasswordResetFinalizeRecord?> GetPasswordResetRequestForFinalizeAsync(
            Guid resetId,
            CancellationToken cancellationToken)
        {
            FinalizeLookupCount++;
            if (!_resets.TryGetValue(resetId, out StoredReset? reset))
            {
                return Task.FromResult<PasswordResetFinalizeRecord?>(new PasswordResetFinalizeRecord(
                    false,
                    PasswordResetService.NotFoundCode,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null));
            }

            return Task.FromResult<PasswordResetFinalizeRecord?>(ToFinalizeRecord(reset));
        }

        public Task<RegisterPasswordResetFailedAttemptResult?> RegisterFailedAttemptAsync(
            Guid resetId,
            Instant failedAt,
            CancellationToken cancellationToken)
        {
            if (!_resets.TryGetValue(resetId, out StoredReset? reset))
            {
                return Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                    false,
                    PasswordResetService.NotFoundCode,
                    null,
                    null,
                    null,
                    null));
            }

            if (reset.ConsumedAt is not null)
            {
                return Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                    false,
                    PasswordResetService.ConsumedCode,
                    reset.AccountId,
                    reset.AttemptCount,
                    reset.MaxAttempts,
                    reset.CancelledAt));
            }

            if (reset.CancelledAt is not null)
            {
                return Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                    false,
                    PasswordResetService.CancelledCode,
                    reset.AccountId,
                    reset.AttemptCount,
                    reset.MaxAttempts,
                    reset.CancelledAt));
            }

            if (reset.ExpiresAt <= failedAt)
            {
                return Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                    false,
                    PasswordResetService.ExpiredCode,
                    reset.AccountId,
                    reset.AttemptCount,
                    reset.MaxAttempts,
                    reset.CancelledAt));
            }

            reset.AttemptCount++;
            if (reset.AttemptCount >= reset.MaxAttempts)
            {
                reset.CancelledAt = failedAt;
                return Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                    false,
                    PasswordResetService.AttemptsExceededCode,
                    reset.AccountId,
                    reset.AttemptCount,
                    reset.MaxAttempts,
                    reset.CancelledAt));
            }

            return Task.FromResult<RegisterPasswordResetFailedAttemptResult?>(new RegisterPasswordResetFailedAttemptResult(
                true,
                "PASSWORD_RESET_ATTEMPT_RECORDED",
                reset.AccountId,
                reset.AttemptCount,
                reset.MaxAttempts,
                null));
        }

        public async Task<PromotePasswordResetResult?> PromotePasswordResetAsync(
            PromotePasswordResetDbCommand command,
            CancellationToken cancellationToken)
        {
            await AwaitPromotionRaceGate();

            lock (_sync)
            {
                if (!_resets.TryGetValue(command.PasswordResetRequestId, out StoredReset? reset))
                {
                    return new PromotePasswordResetResult(
                        false,
                        PasswordResetService.NotFoundCode,
                        null,
                        null,
                        null);
                }

                if (reset.AccountId != command.AccountId)
                {
                    return new PromotePasswordResetResult(
                        false,
                        PasswordResetService.AccountMismatchCode,
                        reset.AccountId,
                        null,
                        null);
                }

                StoredAccount? account = _accounts.FirstOrDefault(candidate => candidate.AccountId == reset.AccountId);
                if (account is null)
                {
                    return new PromotePasswordResetResult(
                        false,
                        PasswordResetService.AccountNotFoundCode,
                        reset.AccountId,
                        null,
                        null);
                }

                Instant now = command.PromotedAt;
                if (reset.ExpiresAt <= now)
                {
                    return new PromotePasswordResetResult(
                        false,
                        PasswordResetService.ExpiredCode,
                        reset.AccountId,
                        null,
                        null);
                }

                if (reset.ConsumedAt is not null)
                {
                    return new PromotePasswordResetResult(
                        false,
                        PasswordResetService.ConsumedCode,
                        reset.AccountId,
                        account.SecurityStamp,
                        reset.ConsumedAt);
                }

                if (reset.CancelledAt is not null)
                {
                    return new PromotePasswordResetResult(
                        false,
                        PasswordResetService.CancelledCode,
                        reset.AccountId,
                        account.SecurityStamp,
                        null);
                }

                reset.ConsumedAt = now;
                account.PasswordPromoted = true;
                account.SecurityStamp = command.NewSecurityStamp;
                account.ExistingSessionsInvalidated = true;
                PromotionCount++;

                return new PromotePasswordResetResult(
                    true,
                    PasswordResetService.CompletedCode,
                    account.AccountId,
                    account.SecurityStamp,
                    reset.ConsumedAt);
            }
        }

        public Task<CancelPasswordResetRequestResult?> CancelPasswordResetRequestAsync(
            Guid resetId,
            Instant cancelledAt,
            string reasonCode,
            CancellationToken cancellationToken)
        {
            if (!_resets.TryGetValue(resetId, out StoredReset? reset))
            {
                return Task.FromResult<CancelPasswordResetRequestResult?>(new CancelPasswordResetRequestResult(
                    false,
                    PasswordResetService.NotFoundCode,
                    null,
                    null));
            }

            if (reset.ConsumedAt is not null)
            {
                return Task.FromResult<CancelPasswordResetRequestResult?>(new CancelPasswordResetRequestResult(
                    false,
                    PasswordResetService.ConsumedCode,
                    reset.AccountId,
                    reset.ConsumedAt));
            }

            if (reset.CancelledAt is not null)
            {
                return Task.FromResult<CancelPasswordResetRequestResult?>(new CancelPasswordResetRequestResult(
                    false,
                    PasswordResetService.CancelledCode,
                    reset.AccountId,
                    reset.CancelledAt));
            }

            reset.CancelledAt = cancelledAt;
            CancelCount++;
            return Task.FromResult<CancelPasswordResetRequestResult?>(new CancelPasswordResetRequestResult(
                true,
                reasonCode,
                reset.AccountId,
                reset.CancelledAt));
        }


        public Task<PasswordResetSession?> GetPendingPasswordResetSessionAsync(
            string resetAccessTokenHash,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<PasswordResetSession?>(null);
        }

        public Task<PasswordResetSessionCommandResult?> UpsertPendingPasswordResetSessionAsync(
            PasswordResetSession session,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<PasswordResetSessionCommandResult?>(new PasswordResetSessionCommandResult(true, "PASSWORD_RESET_SESSION_SAVED"));
        }

        public Task<PasswordResetSessionCommandResult?> RevokePendingPasswordResetSessionAsync(
            string resetAccessTokenHash,
            Instant revokedAt,
            string reasonCode,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<PasswordResetSessionCommandResult?>(new PasswordResetSessionCommandResult(true, reasonCode));
        }

        public Task<PasswordResetRateLimitResult?> RegisterRequestRateLimitAsync(
            PasswordResetRateLimitDbCommand command,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<PasswordResetRateLimitResult?>(new PasswordResetRateLimitResult(
                true,
                "PASSWORD_RESET_RATE_LIMIT_ACCEPTED",
                1,
                null,
                null));
        }

        public Task<PasswordResetCleanupResult?> CleanupExpiredPasswordResetRequestsAsync(
            Instant now,
            Period retention,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<PasswordResetCleanupResult?>(new PasswordResetCleanupResult(true, "PASSWORD_RESET_CLEANUP_COMPLETED", 0, 0));
        }

        public Task<PasswordResetRateLimitCleanupResult?> CleanupPasswordResetRateLimitsAsync(
            Instant now,
            Period retention,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<PasswordResetRateLimitCleanupResult?>(new PasswordResetRateLimitCleanupResult(true, "PASSWORD_RESET_RATE_LIMIT_CLEANUP_COMPLETED", 0));
        }

        private PasswordResetFinalizeRecord ToFinalizeRecord(StoredReset reset)
        {
            StoredAccount? account = _accounts.FirstOrDefault(candidate => candidate.AccountId == reset.AccountId);
            Instant now = _clock.GetCurrentInstant();
            if (reset.ExpiresAt <= now)
            {
                return reset.AsFinalizeRecord(false, PasswordResetService.ExpiredCode, account);
            }

            if (reset.ConsumedAt is not null)
            {
                return reset.AsFinalizeRecord(false, PasswordResetService.ConsumedCode, account);
            }

            if (reset.CancelledAt is not null)
            {
                return reset.AsFinalizeRecord(false, PasswordResetService.CancelledCode, account);
            }

            if (reset.AttemptCount >= reset.MaxAttempts)
            {
                return reset.AsFinalizeRecord(false, PasswordResetService.AttemptsExceededCode, account);
            }

            return reset.AsFinalizeRecord(true, PasswordResetService.ReadyCode, account);
        }
    }

    private sealed class CapturingPasswordResetDeliveryService : IPasswordResetDeliveryService
    {
        public List<PasswordResetDeliveryCommand> Deliveries { get; } = new();

        public PasswordResetDeliveryCommand? LastDelivery => Deliveries.LastOrDefault();

        public PasswordResetDeliveryResult NextResult { get; set; } = new(true, PasswordResetDeliveryService.SentCode);

        public Task<PasswordResetDeliveryResult> SendPasswordResetCode(
            PasswordResetDeliveryCommand command,
            CancellationToken cancellationToken)
        {
            Deliveries.Add(command);
            return Task.FromResult(NextResult);
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
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentException("password is required", nameof(password));
            }

            return new PasswordResetPasswordMaterial(
                Enumerable.Repeat((byte)1, AccountCryptoSizes.PasswordHashBytes).ToArray(),
                Enumerable.Repeat((byte)2, AccountCryptoSizes.SaltOneBytes).ToArray(),
                Enumerable.Repeat((byte)3, AccountCryptoSizes.SivBytes).ToArray(),
                Enumerable.Repeat((byte)4, AccountCryptoSizes.NonceBytes).ToArray());
        }
    }

    private sealed class StoredAccount
    {
        public StoredAccount(
            Guid accountId,
            string emailAddress,
            string username,
            string phoneNumber,
            string phoneCountryCode,
            Guid securityStamp,
            bool emailVerified,
            bool smsVerified,
            bool authenticatorVerified)
        {
            AccountId = accountId;
            EmailAddress = emailAddress;
            Username = username;
            PhoneNumber = phoneNumber;
            PhoneCountryCode = phoneCountryCode;
            SecurityStamp = securityStamp;
            SecurityStampAtStart = securityStamp;
            EmailVerified = emailVerified;
            SmsVerified = smsVerified;
            AuthenticatorVerified = authenticatorVerified;
        }

        public Guid AccountId { get; }

        public string EmailAddress { get; }

        public string Username { get; }

        public string PhoneNumber { get; }

        public string PhoneCountryCode { get; }

        public Guid SecurityStamp { get; set; }

        public Guid SecurityStampAtStart { get; }

        public bool EmailVerified { get; set; }

        public bool SmsVerified { get; set; }

        public bool AuthenticatorVerified { get; set; }

        public bool PasswordPromoted { get; set; }

        public Instant? CutOff { get; set; }

        public bool ExistingSessionsInvalidated { get; set; }

        public bool Matches(string identifier)
        {
            string normalized = identifier.Trim();
            return string.Equals(normalized, EmailAddress, StringComparison.OrdinalIgnoreCase)
                || string.Equals(normalized, Username, StringComparison.OrdinalIgnoreCase)
                || string.Equals(Digits(normalized), Digits(PhoneCountryCode + PhoneNumber), StringComparison.Ordinal);
        }

        private static string Digits(string value)
        {
            return new string(value.Where(char.IsDigit).ToArray());
        }
    }

    private sealed class StoredReset
    {
        public StoredReset(
            Guid resetId,
            Guid accountId,
            string method,
            string? deliveryChannel,
            string? keyCodeHash,
            int? keyCodeHashVersion,
            bool requiresKeyCode,
            bool requiresTotp,
            Instant createdAt,
            Instant expiresAt,
            int maxAttempts,
            Guid accountSecurityStampAtRequest)
        {
            ResetId = resetId;
            AccountId = accountId;
            Method = method;
            DeliveryChannel = deliveryChannel;
            KeyCodeHash = keyCodeHash;
            KeyCodeHashVersion = keyCodeHashVersion;
            RequiresKeyCode = requiresKeyCode;
            RequiresTotp = requiresTotp;
            CreatedAt = createdAt;
            ExpiresAt = expiresAt;
            MaxAttempts = maxAttempts;
            AccountSecurityStampAtRequest = accountSecurityStampAtRequest;
        }

        public Guid ResetId { get; }

        public Guid AccountId { get; }

        public string Method { get; }

        public string? DeliveryChannel { get; }

        public string? KeyCodeHash { get; }

        public int? KeyCodeHashVersion { get; }

        public bool RequiresKeyCode { get; }

        public bool RequiresTotp { get; }

        public Instant CreatedAt { get; }

        public Instant ExpiresAt { get; }

        public Instant? ConsumedAt { get; set; }

        public Instant? CancelledAt { get; set; }

        public int AttemptCount { get; set; }

        public int MaxAttempts { get; }

        public Guid AccountSecurityStampAtRequest { get; }

        public PasswordResetFinalizeRecord AsFinalizeRecord(bool result, string code, StoredAccount? account = null)
        {
            return new PasswordResetFinalizeRecord(
                result,
                code,
                ResetId,
                AccountId,
                Method,
                DeliveryChannel,
                KeyCodeHash,
                KeyCodeHashVersion,
                RequiresKeyCode,
                RequiresTotp,
                ExpiresAt,
                ConsumedAt,
                CancelledAt,
                AttemptCount,
                MaxAttempts,
                AccountSecurityStampAtRequest,
                account?.EmailVerified,
                account?.SmsVerified,
                account?.AuthenticatorVerified,
                account?.EmailAddress,
                account?.PhoneNumber,
                account?.PhoneCountryCode);
        }
    }
}
