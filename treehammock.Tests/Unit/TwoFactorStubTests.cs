using Microsoft.AspNetCore.Http;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class TwoFactorStubTests
{
    [Fact]
    public async Task SetupTwoFactorMethod_email_persists_pending_setup_and_sends_code()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "Reader@Example.Test", null, true);
        harness.AccountRepo.ViewAccount(session.accountId, session.accountSecurityStamp)
            .Returns(Task.FromResult<AccountViewResult?>(AccountEmailView("reader@example.test")));

        harness.AccountRepo.BeginTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<string>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Is("reader@example.test"),
                Arg.Is<string?>(value => value == null),
                Arg.Is<string?>(value => value == null),
                Arg.Is<string?>(value => value == null),
                true)
            .Returns(Task.FromResult<TwoFactorSetupCommandResult?>(new TwoFactorSetupCommandResult(true, "TWO_FACTOR_SETUP_PENDING", 0, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)))));
        harness.TwoFactorService.SetupEmail("reader@example.test", Arg.Any<string>()).Returns(Task.FromResult(true));

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_PENDING");
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBeTrue();
        await harness.TwoFactorService.Received(1).SetupEmail("reader@example.test", Arg.Any<string>());
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelTwoFactorSetup(default, default, default, default!);
    }

    [Fact]
    public async Task SetupTwoFactorMethod_sms_persists_pending_setup_and_sends_code()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, "5555550101", 1, false);

        harness.AccountRepo.BeginTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.SMS_KEY,
                Arg.Any<string>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Is<string?>(value => value == null),
                Arg.Is("5555550101"),
                Arg.Is("1"),
                Arg.Is<string?>(value => value == null),
                false)
            .Returns(Task.FromResult<TwoFactorSetupCommandResult?>(new TwoFactorSetupCommandResult(true, "TWO_FACTOR_SETUP_PENDING", 0, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)))));
        harness.TwoFactorService.SetupSMS("+15555550101", Arg.Any<string>()).Returns(Task.FromResult<bool?>(true));

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status202Accepted);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_PENDING");
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBeTrue();
        await harness.TwoFactorService.Received(1).SetupSMS("+15555550101", Arg.Any<string>());
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelTwoFactorSetup(default, default, default, default!);
    }

    [Fact]
    public async Task SetupTwoFactorMethod_provider_failure_cancels_pending_setup()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "reader@example.test", null, true);
        harness.AccountRepo.ViewAccount(session.accountId, session.accountSecurityStamp)
            .Returns(Task.FromResult<AccountViewResult?>(AccountEmailView("reader@example.test")));

        harness.AccountRepo.BeginTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<string>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Is("reader@example.test"),
                Arg.Is<string?>(value => value == null),
                Arg.Is<string?>(value => value == null),
                Arg.Is<string?>(value => value == null),
                true)
            .Returns(Task.FromResult<TwoFactorSetupCommandResult?>(new TwoFactorSetupCommandResult(true, "TWO_FACTOR_SETUP_PENDING", 0, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)))));
        harness.TwoFactorService.SetupEmail("reader@example.test", Arg.Any<string>()).Returns(Task.FromResult(false));
        harness.AccountRepo.CancelTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<string>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "TWO_FACTOR_SETUP_CANCELLED")));

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_PROVIDER_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBeFalse();
        await harness.AccountRepo.Received(1).CancelTwoFactorSetup(session.accountId, session.accountSecurityStamp, TwoFactorAuthMethod.EMAIL, Arg.Any<string>());
    }

    [Fact]
    public async Task SetupTwoFactorMethod_email_rejects_contact_that_does_not_match_account_email()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "attacker@example.test", null, true);
        harness.AccountRepo.ViewAccount(session.accountId, session.accountSecurityStamp)
            .Returns(Task.FromResult<AccountViewResult?>(AccountEmailView("reader@example.test")));

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.contact));
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().BeginTwoFactorSetup(default, default, default, default!, default, default, default, default, default, default, default);
        await harness.TwoFactorService.DidNotReceiveWithAnyArgs().SetupEmail(default!, default!);
    }

    [Fact]
    public async Task SetupTwoFactorMethod_requires_authenticated_session()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "reader@example.test", null, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.data.ShouldNotBeNull();
        envelope.data!.status.ShouldBeFalse();
    }

    [Fact]
    public async Task SetupTwoFactorMethod_persistence_failure_returns_500()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "reader@example.test", null, true);
        harness.AccountRepo.ViewAccount(session.accountId, session.accountSecurityStamp)
            .Returns(Task.FromResult<AccountViewResult?>(AccountEmailView("reader@example.test")));

        harness.AccountRepo.BeginTwoFactorSetup(
                Arg.Any<Guid>(),
                Arg.Any<Guid>(),
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<string>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Is("reader@example.test"),
                Arg.Is<string?>(value => value == null),
                Arg.Is<string?>(value => value == null),
                Arg.Is<string?>(value => value == null),
                true)
            .Returns(Task.FromResult<TwoFactorSetupCommandResult?>(null));

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_PERSISTENCE_FAILED");
        await harness.TwoFactorService.DidNotReceiveWithAnyArgs().SetupEmail(default!, default!);
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_correct_code_promotes_pending_setup()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, "123456");

        harness.AccountRepo.VerifyTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.SMS_KEY,
                Arg.Any<string>(),
                (short)harness.LoginSettings.TwoAuthRetryLimit,
                Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorSetupVerificationCommandResult?>(
                new TwoFactorSetupVerificationCommandResult(true, "TWO_FACTOR_SETUP_VERIFIED", 0, null)));

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status200OK);
        envelope.success.ShouldBeTrue();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_VERIFIED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.SUCCESS);
        await harness.AccountRepo.Received(1).VerifyTwoFactorSetup(
            session.accountId,
            session.accountSecurityStamp,
            TwoFactorAuthMethod.SMS_KEY,
            Arg.Any<string>(),
            (short)harness.LoginSettings.TwoAuthRetryLimit,
            Arg.Any<Instant>());
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.TwoFactorSetup && key.Dimension == AbuseCounterDimension.Account),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_incorrect_code_returns_incorrect_without_promotion()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "000000");

        harness.AccountRepo.VerifyTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<string>(),
                (short)harness.LoginSettings.TwoAuthRetryLimit,
                Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorSetupVerificationCommandResult?>(
                new TwoFactorSetupVerificationCommandResult(false, "TWO_FACTOR_SETUP_INCORRECT", 1, SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(5)))));

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_INCORRECT");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.INCORRECT);
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_expired_code_returns_failure()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "123456");

        harness.AccountRepo.VerifyTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<string>(),
                (short)harness.LoginSettings.TwoAuthRetryLimit,
                Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorSetupVerificationCommandResult?>(
                new TwoFactorSetupVerificationCommandResult(false, "TWO_FACTOR_SETUP_EXPIRED", (short)harness.LoginSettings.TwoAuthRetryLimit, SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromMinutes(1)))));

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_EXPIRED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_attempt_limit_returns_incorrect()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var session = harness.SetAuthenticatedSession();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, "000000");

        harness.AccountRepo.VerifyTwoFactorSetup(
                session.accountId,
                session.accountSecurityStamp,
                TwoFactorAuthMethod.SMS_KEY,
                Arg.Any<string>(),
                (short)harness.LoginSettings.TwoAuthRetryLimit,
                Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorSetupVerificationCommandResult?>(
                new TwoFactorSetupVerificationCommandResult(false, "TWO_FACTOR_SETUP_ATTEMPT_LIMIT", (short)harness.LoginSettings.TwoAuthRetryLimit, SystemClock.Instance.GetCurrentInstant())));

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_ATTEMPT_LIMIT");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.INCORRECT);
    }


    [Fact]
    public async Task VerifyTwoFactorMethod_throttles_setup_verification_before_sql_when_counter_exhausted()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        harness.SetAuthenticatedSession();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "123456");

        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.TwoFactorSetup && key.Dimension == AbuseCounterDimension.Account),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 6,
                Limit: 5,
                Window: TimeSpan.FromMinutes(10),
                RetryAfter: TimeSpan.FromSeconds(30),
                ReasonCode: AbuseReasonCodes.CounterLimitExceeded)));

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status429TooManyRequests);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.TwoFactorSetupAttemptsExceeded);
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        harness.HttpContext.Response.Headers["Retry-After"].ToString().ShouldBe("30");
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().VerifyTwoFactorSetup(default, default, default, default!, default, default);
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_fails_closed_before_sql_when_setup_counter_store_unavailable()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        harness.SetAuthenticatedSession();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, "123456");

        harness.AbuseCounterStore.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.TwoFactorSetup),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 0,
                Limit: 5,
                Window: TimeSpan.FromMinutes(10),
                RetryAfter: null,
                ReasonCode: AbuseReasonCodes.CounterStoreUnavailable)));

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status503ServiceUnavailable);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().VerifyTwoFactorSetup(default, default, default, default!, default, default);
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_requires_authenticated_session()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, "123456");

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status401Unauthorized);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().VerifyTwoFactorSetup(default, default, default, default!, default, default);
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_persistence_failure_returns_500()
    {
        var harness = new AccountControllerHarness();
        var controller = harness.CreateTwoFactorController();
        harness.SetAuthenticatedSession();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "123456");

        harness.AccountRepo.VerifyTwoFactorSetup(
                Arg.Any<Guid>(),
                Arg.Any<Guid>(),
                TwoFactorAuthMethod.EMAIL,
                Arg.Any<string>(),
                (short)harness.LoginSettings.TwoAuthRetryLimit,
                Arg.Any<Instant>())
            .Returns(Task.FromResult<TwoFactorSetupVerificationCommandResult?>(null));

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_SETUP_VERIFY_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(TwoFactorAuthOutcome.FAILURE);
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_none_sentinel_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.NONE, "reader@example.test", 1, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_rejects_none_sentinel_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.NONE, "123456");

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_blank_contact_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, string.Empty, null, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.contact));
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_invalid_email_contact_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "not-an-email", null, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.contact));
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_authenticator_app_setup_until_provider_is_supported()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.AUTHENTICATOR_APP, "authenticator-app-user", null, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.method));
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_rejects_authenticator_app_setup_verification_until_provider_is_supported()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.AUTHENTICATOR_APP, "123456");

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(VerifyLayeredAuthenticateMethodRequest.method));
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_sms_without_country_code_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, "5555550101", null, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.countryCode));
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_rejects_empty_code_key_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, string.Empty);

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(VerifyLayeredAuthenticateMethodRequest.codeKey));
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_unsupported_method_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest((TwoFactorAuthMethod)999, "reader@example.test", null, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.method));
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_rejects_unsupported_method_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new VerifyLayeredAuthenticateMethodRequest((TwoFactorAuthMethod)999, "123456");

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(VerifyLayeredAuthenticateMethodRequest.method));
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_overlong_contact_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var contact = new string('a', SetupLayeredAuthenticateMethodRequest.MaxContactLength + 1);
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, contact, null, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.contact));
    }

    [Fact]
    public async Task SetupTwoFactorMethod_rejects_invalid_non_sms_country_code_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var request = new SetupLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.EMAIL, "reader@example.test", 0, true);

        var actionResult = await controller.SetupTwoFactorMethod(request);

        ApiResponse<SetupLayeredAuthenticateMethodResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(SetupLayeredAuthenticateMethodRequest.countryCode));
    }

    [Fact]
    public async Task VerifyTwoFactorMethod_rejects_overlong_code_key_as_validation_failure()
    {
        var controller = new AccountControllerHarness().CreateTwoFactorController();
        var codeKey = new string('1', VerifyLayeredAuthenticateMethodRequest.MaxCodeLength + 1);
        var request = new VerifyLayeredAuthenticateMethodRequest(TwoFactorAuthMethod.SMS_KEY, codeKey);

        var actionResult = await controller.VerifyTwoFactorMethod(request);

        ApiResponse<LayeredAuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status400BadRequest);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe(ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(envelope, nameof(VerifyLayeredAuthenticateMethodRequest.codeKey));
    }

    private static AccountViewResult AccountEmailView(string emailAddress)
    {
        return new AccountViewResult(true, "ACCOUNT_VIEW_SUCCEEDED", new AccountProfile
        {
            emailAddress = emailAddress,
            username = "reader",
            createdOn = SystemClock.Instance.GetCurrentInstant(),
            verifyStatus = VerificationStatus.SUCCESSFUL,
            country = Country.NONE,
            features = FeatureSet.basic,
            twoFactorEnabled = false
        });
    }

    private static void AssertHasValidationErrorFor<T>(ApiResponse<T> envelope, string field)
    {
        envelope.errors.ShouldNotBeNull();
        envelope.errors!.ShouldContain(error => error.field == field);
    }
}
