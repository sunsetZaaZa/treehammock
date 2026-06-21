using System.Net;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer;
using treehammock.Models.Activation;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class ActivationServiceTests
{
    [Fact]
    public async Task PlaceActivation_generates_backend_code_persists_it_and_sends_it_to_the_account_email()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? persistedCode = null;
        string? emailedBody = null;
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.ActivationRepo.PlaceActivation(
                accountId,
                accountSecurityStamp,
                "reader@example.com",
                Arg.Do<string>(code => persistedCode = code),
                now,
                DayDuration.MONTHLY,
                DurationRepeat.NONE,
                Arg.Any<Instant>(),
                FeatureSet.premium,
                PlatformBacker.Intra,
                "backend",
                ActivationStatus.PENDING,
                null)
            .Returns(Task.FromResult<ActivationCommandResult?>(new ActivationCommandResult(true, ActivationService.StoredCode, ActivationStatus.PENDING)));

        harness.SmtpService.Send(
                "reader@example.com",
                harness.EmailSubjectSettings.ActivationCode,
                Arg.Do<string>(body => emailedBody = body))
            .Returns(Task.FromResult<bool?>(true));

        ActivationCreateResult result = await harness.Service.PlaceActivation(
            accountId,
            accountSecurityStamp,
            new ActivationCreationRequest("reader@example.com", (uint)FeatureSet.premium, DayDuration.MONTHLY, DurationRepeat.NONE),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(ActivationService.CreatedCode);
        persistedCode.ShouldNotBeNull();
        persistedCode!.Length.ShouldBeGreaterThan(10);
        emailedBody!.ShouldContain(persistedCode);
    }

    [Fact]
    public async Task PlaceActivation_cancels_pending_activation_when_email_delivery_fails()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? persistedCode = null;
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.ActivationRepo.PlaceActivation(
                accountId,
                accountSecurityStamp,
                "reader@example.com",
                Arg.Do<string>(code => persistedCode = code),
                now,
                DayDuration.MONTHLY,
                DurationRepeat.NONE,
                Arg.Any<Instant>(),
                FeatureSet.premium,
                PlatformBacker.Intra,
                "backend",
                ActivationStatus.PENDING,
                null)
            .Returns(Task.FromResult<ActivationCommandResult?>(new ActivationCommandResult(true, ActivationService.StoredCode, ActivationStatus.PENDING)));

        harness.SmtpService.Send(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));

        harness.ActivationRepo.CancelActivationRequest(
                accountId,
                accountSecurityStamp,
                Arg.Any<string>(),
                now)
            .Returns(Task.FromResult<ActivationCommandResult?>(new ActivationCommandResult(true, "ACTIVATION_CANCELLED", ActivationStatus.DISRUPTED)));

        ActivationCreateResult result = await harness.Service.PlaceActivation(
            accountId,
            accountSecurityStamp,
            new ActivationCreationRequest("reader@example.com", (uint)FeatureSet.premium, DayDuration.MONTHLY, DurationRepeat.NONE),
            now);

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(ActivationService.EmailDeliveryFailedCode);
        await harness.ActivationRepo.Received(1).CancelActivationRequest(accountId, accountSecurityStamp, persistedCode!, now);
    }

    [Fact]
    public async Task VerifyActivation_requires_matching_code_and_returns_activation_details()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var activation = new treehammock.DataLayer.ActivationQuery(
            FeatureSet.premium,
            now.Plus(Duration.FromDays(31)),
            DayDuration.MONTHLY,
            DurationRepeat.NONE);

        harness.ActivationRepo.VerifyActivation(accountId, accountSecurityStamp, "reader@example.com", "abc123", now, 0, 1)
            .Returns(Task.FromResult<ActivationVerifyCommandResult?>(new ActivationVerifyCommandResult(true, ActivationService.VerifiedCode, activation)));

        ActivationVerifyResult result = await harness.Service.VerifyActivation(
            accountId,
            accountSecurityStamp,
            new ActivationDetailsRequest("reader@example.com", "abc123"),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(ActivationService.VerifiedCode);
        result.Activation.ShouldBeSameAs(activation);
    }

    [Fact]
    public async Task PlaceActivation_maps_stale_security_stamp_without_sending_email()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.ActivationRepo.PlaceActivation(
                accountId,
                accountSecurityStamp,
                "reader@example.com",
                Arg.Any<string>(),
                now,
                DayDuration.MONTHLY,
                DurationRepeat.NONE,
                Arg.Any<Instant>(),
                FeatureSet.premium,
                PlatformBacker.Intra,
                "backend",
                ActivationStatus.PENDING,
                null)
            .Returns(Task.FromResult<ActivationCommandResult?>(new ActivationCommandResult(false, ActivationService.SecurityStampMismatchCode, null)));

        ActivationCreateResult result = await harness.Service.PlaceActivation(
            accountId,
            accountSecurityStamp,
            new ActivationCreationRequest("reader@example.com", (uint)FeatureSet.premium, DayDuration.MONTHLY, DurationRepeat.NONE),
            now);

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(ActivationService.SecurityStampMismatchCode);
        _ = harness.SmtpService.DidNotReceiveWithAnyArgs().Send(default!, default!, default!);
    }

    [Fact]
    public async Task VerifyActivation_preserves_expired_and_code_mismatch_results()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.ActivationRepo.VerifyActivation(accountId, accountSecurityStamp, "reader@example.com", "expired", now, 0, 1)
            .Returns(Task.FromResult<ActivationVerifyCommandResult?>(new ActivationVerifyCommandResult(false, ActivationService.ExpiredCode, null)));

        harness.ActivationRepo.VerifyActivation(accountId, accountSecurityStamp, "reader@example.com", "wrong", now, 0, 1)
            .Returns(Task.FromResult<ActivationVerifyCommandResult?>(new ActivationVerifyCommandResult(false, ActivationService.CodeMismatchCode, null)));

        ActivationVerifyResult expired = await harness.Service.VerifyActivation(
            accountId,
            accountSecurityStamp,
            new ActivationDetailsRequest("reader@example.com", "expired"),
            now);

        ActivationVerifyResult mismatch = await harness.Service.VerifyActivation(
            accountId,
            accountSecurityStamp,
            new ActivationDetailsRequest("reader@example.com", "wrong"),
            now);

        expired.Result.ShouldBeFalse();
        expired.Code.ShouldBe(ActivationService.ExpiredCode);
        mismatch.Result.ShouldBeFalse();
        mismatch.Code.ShouldBe(ActivationService.CodeMismatchCode);
    }



    [Fact]
    public void Activation_abuse_key_factory_uses_safe_fingerprints_for_email_and_ip()
    {
        var factory = new ActivationAbuseCounterKeyFactory();
        Guid accountId = Guid.NewGuid();

        AbuseCounterKey account = factory.ForVerifyAccount(accountId);
        AbuseCounterKey email = factory.ForVerifyIdentifier("Reader@Example.com");
        AbuseCounterKey ip = factory.ForVerifyIpAddress("203.0.113.42");

        account.Feature.ShouldBe(AbuseFeature.Activation);
        account.Dimension.ShouldBe(AbuseCounterDimension.Account);
        account.Value.ShouldContain(accountId.ToString("N"));

        email.Feature.ShouldBe(AbuseFeature.Activation);
        email.Dimension.ShouldBe(AbuseCounterDimension.IdentifierFingerprint);
        email.Value.ShouldStartWith("abuse:activation:identifierfingerprint:email-");
        email.Value.ShouldNotContain("Reader");
        email.Value.ShouldNotContain("example.com");

        ip.Feature.ShouldBe(AbuseFeature.Activation);
        ip.Dimension.ShouldBe(AbuseCounterDimension.IpFingerprint);
        ip.Value.ShouldNotContain("203.0.113.42");
    }

    [Fact]
    public async Task VerifyActivation_denies_before_repository_when_activation_policy_is_exhausted()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(false, 6, 5, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(15), AbuseReasonCodes.CounterLimitExceeded)));

        ActivationVerifyResult result = await harness.Service.VerifyActivation(
            accountId,
            accountSecurityStamp,
            new ActivationDetailsRequest("reader@example.com", "wrong-code"),
            now);

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.ActivationVerifyAttemptsExceeded);
        await harness.ActivationRepo.DidNotReceive().VerifyActivation(
            Arg.Any<Guid>(),
            Arg.Any<Guid>(),
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<Instant>(),
            Arg.Any<ushort>(),
            Arg.Any<ushort>());
    }

    [Fact]
    public async Task VerifyActivation_returns_counter_store_unavailable_before_repository_lookup()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.AbuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(false, 0, 5, TimeSpan.FromMinutes(15), null, AbuseReasonCodes.CounterStoreUnavailable)));

        ActivationVerifyResult result = await harness.Service.VerifyActivation(
            accountId,
            accountSecurityStamp,
            new ActivationDetailsRequest("reader@example.com", "abc123"),
            now);

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        await harness.ActivationRepo.DidNotReceive().VerifyActivation(
            Arg.Any<Guid>(),
            Arg.Any<Guid>(),
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<Instant>(),
            Arg.Any<ushort>(),
            Arg.Any<ushort>());
    }

    [Fact]
    public async Task VerifyActivation_resets_activation_verify_counters_after_success()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        var activation = new treehammock.DataLayer.ActivationQuery(
            FeatureSet.premium,
            now.Plus(Duration.FromDays(31)),
            DayDuration.MONTHLY,
            DurationRepeat.NONE);

        harness.ActivationRepo.VerifyActivation(accountId, accountSecurityStamp, "reader@example.com", "abc123", now, 0, 1)
            .Returns(Task.FromResult<ActivationVerifyCommandResult?>(new ActivationVerifyCommandResult(true, ActivationService.VerifiedCode, activation)));

        ActivationVerifyResult result = await harness.Service.VerifyActivation(
            accountId,
            accountSecurityStamp,
            new ActivationDetailsRequest("reader@example.com", "abc123"),
            now);

        result.Result.ShouldBeTrue();
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.Activation && key.Dimension == AbuseCounterDimension.Account),
            Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.Activation && key.Dimension == AbuseCounterDimension.IdentifierFingerprint),
            Arg.Any<CancellationToken>());
        await harness.AbuseCounterStore.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.Activation && key.Dimension == AbuseCounterDimension.IpFingerprint),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PlaceActivation_rejects_invalid_term_without_persisting_or_sending_email()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        ActivationCreateResult result = await harness.Service.PlaceActivation(
            accountId,
            accountSecurityStamp,
            new ActivationCreationRequest("reader@example.com", (uint)FeatureSet.premium, (DayDuration)99, DurationRepeat.NONE),
            now);

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(ActivationService.InvalidTermCode);
        _ = harness.ActivationRepo.DidNotReceiveWithAnyArgs().PlaceActivation(
            default, default, default!, default!, default, default, default, default, default, default, default!, default, default);
        _ = harness.SmtpService.DidNotReceiveWithAnyArgs().Send(default!, default!, default!);
    }

    [Fact]
    public async Task PlaceActivation_rejects_invalid_recycle_without_persisting_or_sending_email()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        ActivationCreateResult result = await harness.Service.PlaceActivation(
            accountId,
            accountSecurityStamp,
            new ActivationCreationRequest("reader@example.com", (uint)FeatureSet.premium, DayDuration.MONTHLY, (DurationRepeat)99),
            now);

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(ActivationService.InvalidRecycleCode);
        _ = harness.ActivationRepo.DidNotReceiveWithAnyArgs().PlaceActivation(
            default, default, default!, default!, default, default, default, default, default, default, default!, default, default);
        _ = harness.SmtpService.DidNotReceiveWithAnyArgs().Send(default!, default!, default!);
    }

    private static ActivationServiceHarness CreateHarness()
    {
        var activationRepo = Substitute.For<IActivationRepo>();
        var smtpService = Substitute.For<ISMTPService>();
        var abuseCounterStore = Substitute.For<IAbuseCounterStore>();
        abuseCounterStore.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(true, 1, limit.MaxAttempts, limit.Window, null, null));
            });
        abuseCounterStore.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        var httpContextAccessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext()
        };
        httpContextAccessor.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.42");
        var emailSubjectSettings = new EmailSubjectSettings
        {
            AccountVerify = "Verify your account",
            AccountVerifyResend = "Resend verification",
            AccountEmailChangeVerify = "Verify new email",
            AccountDeleteVerify = "Verify deletion",
            TwoFactorSetup = "Setup 2FA",
            TwoFactorKeyOutbound = "2FA code",
            TwoFactorDelete = "Delete 2FA",
            ActivationCode = "Activation code"
        };

        var service = new ActivationService(
            activationRepo,
            smtpService,
            Options.Create(emailSubjectSettings),
            NullLogger<ActivationService>.Instance,
            deliveryAbuseThrottleService: null,
            activationAbuseCounterKeyFactory: new ActivationAbuseCounterKeyFactory(),
            abuseCounterStore: abuseCounterStore,
            abuseControlSettings: Options.Create(new AbuseControlSettings()),
            httpContextAccessor: httpContextAccessor);

        return new ActivationServiceHarness(service, activationRepo, smtpService, emailSubjectSettings, abuseCounterStore);
    }

    private sealed record ActivationServiceHarness(
        ActivationService Service,
        IActivationRepo ActivationRepo,
        ISMTPService SmtpService,
        EmailSubjectSettings EmailSubjectSettings,
        IAbuseCounterStore AbuseCounterStore);
}
