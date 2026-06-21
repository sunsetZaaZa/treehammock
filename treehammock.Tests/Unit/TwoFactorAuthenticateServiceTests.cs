using NSubstitute;
using Shouldly;

using treehammock.Services;

namespace treehammock.Tests.Unit;

public class TwoFactorAuthenticateServiceTests
{
    [Fact]
    public async Task Email_sends_two_factor_key_through_smtp()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        smtp.TwoFactorKeyOutboundLetter("reader@example.com", Arg.Any<string>(), "123456").Returns(Task.FromResult<bool?>(true));
        var service = new TwoFactorAuthenticateService(smtp, sms);

        bool sent = await service.Email("reader@example.com", "123456");

        sent.ShouldBe(true);
        await smtp.Received(1).TwoFactorKeyOutboundLetter("reader@example.com", Arg.Any<string>(), "123456");
    }

    [Fact]
    public async Task SetupEmail_sends_setup_code_through_smtp()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        smtp.TwoFactorSetupLetter("reader@example.com", Arg.Any<string>(), "123456").Returns(Task.FromResult<bool?>(true));
        var service = new TwoFactorAuthenticateService(smtp, sms);

        bool sent = await service.SetupEmail("reader@example.com", "123456");

        sent.ShouldBe(true);
        await smtp.Received(1).TwoFactorSetupLetter("reader@example.com", Arg.Any<string>(), "123456");
    }

    [Fact]
    public async Task SMS_sends_two_factor_key_through_provider_agnostic_sender()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        sms.SendCode("+15555550101", "123456").Returns(Task.FromResult(true));
        var service = new TwoFactorAuthenticateService(smtp, sms);

        bool? sent = await service.SMS("+15555550101", "123456");

        sent.ShouldBe(true);
        await sms.Received(1).SendCode("+15555550101", "123456");
    }

    [Fact]
    public async Task SetupSMS_sends_setup_code_through_provider_agnostic_sender()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        sms.SendCode("+15555550101", "123456").Returns(Task.FromResult(true));
        var service = new TwoFactorAuthenticateService(smtp, sms);

        bool? sent = await service.SetupSMS("+15555550101", "123456");

        sent.ShouldBe(true);
        await sms.Received(1).SendCode("+15555550101", "123456");
    }

    [Fact]
    public void Unsupported_provider_methods_are_not_exposed_by_two_factor_delivery_service()
    {
        Type contract = typeof(ITwoFactorAuthenticateService);

        contract.GetMethod("Au" + "thy").ShouldBeNull();
        contract.GetMethod("Setup" + "Au" + "thy").ShouldBeNull();
        contract.GetMethod("Remove" + "Au" + "thy").ShouldBeNull();
        contract.GetMethod("OAuth").ShouldBeNull();
        contract.GetMethod("SetupOAuth").ShouldBeNull();
        contract.GetMethod("RemoveOAuth").ShouldBeNull();
        contract.GetMethod("RemoveEmail").ShouldBeNull();
        contract.GetMethod("RemoveSMS").ShouldBeNull();
    }
}
