using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.DataLayer;
using treehammock.Models.Activation;
using treehammock.Models.Recovery;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class DeliveryAbuseThrottleApplicationTests
{
    [Fact]
    public async Task Password_reset_delivery_throttle_denial_suppresses_provider_send()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var throttle = new CapturingDeliveryAbuseThrottleService(allow: false);
        var service = new PasswordResetDeliveryService(
            smtp,
            sms,
            Options.Create(new EmailSubjectSettings()),
            Options.Create(new EmailTemplateSettings()),
            NullLogger<PasswordResetDeliveryService>.Instance,
            throttle);

        PasswordResetDeliveryResult result = await service.SendPasswordResetCode(
            new PasswordResetDeliveryCommand(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "email",
                "email",
                "r***r@example.com",
                "reader@example.com",
                "123456",
                SystemClock.Instance.GetCurrentInstant()),
            CancellationToken.None);

        result.Sent.ShouldBeFalse();
        throttle.AllowChecks.ShouldBe(1);
        await smtp.DidNotReceiveWithAnyArgs().PasswordResetCodeLetter(default!, default!, default!, default!, default!);
        await sms.DidNotReceiveWithAnyArgs().SendMessage(default!, default!);
    }

    [Fact]
    public async Task Activation_delivery_throttle_denial_suppresses_provider_send()
    {
        var repo = Substitute.For<IActivationRepo>();
        var smtp = Substitute.For<ISMTPService>();
        var throttle = new CapturingDeliveryAbuseThrottleService(allow: false);
        Guid accountId = Guid.NewGuid();
        Guid stamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        repo.PlaceActivation(
                accountId,
                stamp,
                "reader@example.com",
                Arg.Any<string>(),
                now,
                DayDuration.DAILY,
                DurationRepeat.NONE,
                Arg.Any<Instant>(),
                FeatureSet.basic,
                PlatformBacker.Intra,
                Arg.Any<string>(),
                ActivationStatus.PENDING,
                Arg.Any<Period?>())
            .Returns(Task.FromResult<ActivationCommandResult?>(new ActivationCommandResult(true, ActivationService.StoredCode, ActivationStatus.PENDING)));
        repo.CancelActivationRequest(accountId, stamp, Arg.Any<string>(), now)
            .Returns(Task.FromResult<ActivationCommandResult?>(new ActivationCommandResult(true, ActivationService.EmailDeliveryFailedCode, ActivationStatus.DISRUPTED)));

        var service = new ActivationService(
            repo,
            smtp,
            Options.Create(new EmailSubjectSettings()),
            NullLogger<ActivationService>.Instance,
            throttle);

        ActivationCreateResult result = await service.PlaceActivation(
            accountId,
            stamp,
            new ActivationCreationRequest("reader@example.com", (uint)FeatureSet.basic, DayDuration.DAILY, DurationRepeat.NONE),
            now);

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(ActivationService.EmailDeliveryFailedCode);
        throttle.AllowChecks.ShouldBe(1);
        await smtp.DidNotReceiveWithAnyArgs().Send(default!, default!, default!);
    }

    [Fact]
    public async Task Account_unlock_delivery_throttle_denial_preserves_generic_response_and_suppresses_provider_send()
    {
        var repo = Substitute.For<IAccountRecoveryRepo>();
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var throttle = new CapturingDeliveryAbuseThrottleService(allow: false);
        Guid accountId = Guid.NewGuid();
        Guid stamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(new AccountRecoveryLookupResult(
                true,
                AccountRecoveryService.PendingCode,
                accountId,
                "reader@example.com",
                null,
                null,
                stamp,
                now.Plus(Duration.FromMinutes(10)))));
        repo.BeginUnlock(accountId, Arg.Any<string>(), now, Arg.Any<Instant>(), AccountRecovery_Status.STANDBY, AccountUnlockDeliveryMethod.EMAIL, stamp, Arg.Any<Instant>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STANDBY));
        repo.CancelUnlock(accountId, Arg.Any<string>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.CANCELED));

        var service = new AccountRecoveryService(
            repo,
            smtp,
            sms,
            Options.Create(new EmailSubjectSettings()),
            NullLogger<AccountRecoveryService>.Instance,
            throttle);

        AccountRecoveryStartResult result = await service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com", AccountUnlockDeliveryMethod.EMAIL),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        throttle.AllowChecks.ShouldBe(1);
        await smtp.DidNotReceiveWithAnyArgs().AccountUnlockLetter(default!, default!, default!);
        await sms.DidNotReceiveWithAnyArgs().SendCode(default!, default!);
    }

    [Fact]
    public async Task Two_factor_delivery_throttle_denial_suppresses_provider_send()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var throttle = new CapturingDeliveryAbuseThrottleService(allow: false);
        var service = new TwoFactorAuthenticateService(
            smtp,
            sms,
            Options.Create(new EmailSubjectSettings()),
            throttle);

        bool sent = await service.Email("reader@example.com", "123456", Guid.NewGuid());

        sent.ShouldBeFalse();
        throttle.AllowChecks.ShouldBe(1);
        await smtp.DidNotReceiveWithAnyArgs().TwoFactorKeyOutboundLetter(default!, default!, default!);
        await sms.DidNotReceiveWithAnyArgs().SendCode(default!, default!);
    }


    [Fact]
    public async Task Password_reset_email_provider_failure_records_delivery_provider_failure()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var throttle = new CapturingDeliveryAbuseThrottleService(allow: true);
        var service = new PasswordResetDeliveryService(
            smtp,
            sms,
            Options.Create(new EmailSubjectSettings()),
            Options.Create(new EmailTemplateSettings()),
            NullLogger<PasswordResetDeliveryService>.Instance,
            throttle);
        smtp.PasswordResetCodeLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));

        PasswordResetDeliveryResult result = await service.SendPasswordResetCode(
            new PasswordResetDeliveryCommand(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "email",
                "email",
                "r***r@example.com",
                "reader@example.com",
                "123456",
                SystemClock.Instance.GetCurrentInstant()),
            CancellationToken.None);

        result.Sent.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetDeliveryService.FailedCode);
        throttle.AllowChecks.ShouldBe(1);
        throttle.ProviderFailures.ShouldBe(1);
    }

    private sealed class CapturingDeliveryAbuseThrottleService : IDeliveryAbuseThrottleService
    {
        private readonly bool _allow;

        public CapturingDeliveryAbuseThrottleService(bool allow)
        {
            _allow = allow;
        }

        public int AllowChecks { get; private set; }

        public int ProviderFailures { get; private set; }

        public Task<AbuseDecision> ShouldAllowDeliveryAsync(
            DeliveryAbuseThrottleRequest request,
            CancellationToken cancellationToken = default)
        {
            AllowChecks++;
            return Task.FromResult(_allow
                ? AbuseDecision.Allow()
                : AbuseDecision.Deny(AbuseReasonCodes.DeliveryThrottleExceeded, TimeSpan.FromMinutes(15)));
        }

        public Task RecordProviderFailureAsync(
            DeliveryAbuseThrottleRequest request,
            CancellationToken cancellationToken = default)
        {
            ProviderFailures++;
            return Task.CompletedTask;
        }
    }
}
