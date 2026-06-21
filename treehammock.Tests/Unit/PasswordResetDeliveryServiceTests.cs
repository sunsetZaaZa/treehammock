using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class PasswordResetDeliveryServiceTests
{
    [Fact]
    public async Task SendPasswordResetCode_sends_email_with_password_reset_template_subject_and_expiration()
    {
        var harness = CreateHarness();
        Instant expiresAt = Instant.FromUtc(2026, 5, 19, 22, 30);

        harness.SmtpService.PasswordResetCodeLetter(
                "reader@example.com",
                "Your Treehammock password reset code",
                "49382710",
                "2026-05-19 22:30 UTC",
                "r***r@example.com")
            .Returns(Task.FromResult<bool?>(true));

        PasswordResetDeliveryResult result = await harness.Service.SendPasswordResetCode(
            new PasswordResetDeliveryCommand(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "email",
                "email",
                "r***r@example.com",
                "reader@example.com",
                "49382710",
                expiresAt),
            CancellationToken.None);

        result.Sent.ShouldBeTrue();
        result.Code.ShouldBe(PasswordResetDeliveryService.SentCode);
        await harness.SmtpService.Received(1).PasswordResetCodeLetter(
            "reader@example.com",
            "Your Treehammock password reset code",
            "49382710",
            "2026-05-19 22:30 UTC",
            "r***r@example.com");
        await harness.SmsSender.DidNotReceiveWithAnyArgs().SendMessage(default!, default!);
    }

    [Fact]
    public async Task SendPasswordResetCode_sends_sms_with_rendered_password_reset_template()
    {
        var harness = CreateHarness();
        string? renderedMessage = null;
        Instant expiresAt = Instant.FromUtc(2026, 5, 19, 22, 30);

        harness.SmsSender.SendMessage("+15555550101", Arg.Do<string>(message => renderedMessage = message))
            .Returns(Task.FromResult(true));

        PasswordResetDeliveryResult result = await harness.Service.SendPasswordResetCode(
            new PasswordResetDeliveryCommand(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "sms",
                "sms",
                "***-***-0101",
                "+15555550101",
                "49382710",
                expiresAt),
            CancellationToken.None);

        result.Sent.ShouldBeTrue();
        result.Code.ShouldBe(PasswordResetDeliveryService.SentCode);
        renderedMessage.ShouldNotBeNull();
        renderedMessage.ShouldContain("password reset code");
        renderedMessage.ShouldContain("49382710");
        renderedMessage.ShouldContain("2026-05-19 22:30 UTC");
        await harness.SmtpService.DidNotReceiveWithAnyArgs().PasswordResetCodeLetter(default!, default!, default!, default!, default!);
    }

    [Fact]
    public async Task SendPasswordResetCode_returns_failed_without_throwing_when_email_delivery_fails()
    {
        var harness = CreateHarness();

        harness.SmtpService.PasswordResetCodeLetter(
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<string>(),
                Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(null));

        PasswordResetDeliveryResult result = await harness.Service.SendPasswordResetCode(
            new PasswordResetDeliveryCommand(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "email",
                "email",
                "r***r@example.com",
                "reader@example.com",
                "49382710",
                SystemClock.Instance.GetCurrentInstant()),
            CancellationToken.None);

        result.Sent.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetDeliveryService.FailedCode);
    }

    [Fact]
    public async Task SendPasswordResetCode_rejects_unsupported_delivery_channel()
    {
        var harness = CreateHarness();

        PasswordResetDeliveryResult result = await harness.Service.SendPasswordResetCode(
            new PasswordResetDeliveryCommand(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "email",
                "carrier-pigeon",
                "r***r@example.com",
                "reader@example.com",
                "49382710",
                SystemClock.Instance.GetCurrentInstant()),
            CancellationToken.None);

        result.Sent.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetDeliveryService.UnsupportedDeliveryChannelCode);
        await harness.SmtpService.DidNotReceiveWithAnyArgs().PasswordResetCodeLetter(default!, default!, default!, default!, default!);
        await harness.SmsSender.DidNotReceiveWithAnyArgs().SendMessage(default!, default!);
    }

    private static Harness CreateHarness()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var service = new PasswordResetDeliveryService(
            smtp,
            sms,
            Options.Create(new EmailSubjectSettings { PasswordResetCode = "Your Treehammock password reset code" }),
            Options.Create(new EmailTemplateSettings { PasswordResetSmsCode = "sms_templates/PasswordResetCode.txt" }),
            NullLogger<PasswordResetDeliveryService>.Instance);

        return new Harness(service, smtp, sms);
    }

    private sealed record Harness(
        PasswordResetDeliveryService Service,
        ISMTPService SmtpService,
        ISmsSender SmsSender);
}
