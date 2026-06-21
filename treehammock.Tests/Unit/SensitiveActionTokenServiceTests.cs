using System.Text;

using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.DataLayer.Security;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class SensitiveActionTokenServiceTests
{
    private const string CorrectPassword = "CorrectHorseBatteryStaple1!";

    [Fact]
    public async Task Reauthenticate_issues_hashed_scoped_token_when_password_is_correct()
    {
        var repo = Substitute.For<ISensitiveActionTokenRepo>();
        var settings = Options.Create(new SensitiveActionSettings
        {
            TokenBytes = 32,
            ExpirationMinutes = 10,
            ConsumeExistingTokensOnIssue = true
        });
        var service = new AccountSensitiveActionService(repo, settings);
        Guid accountId = Guid.NewGuid();
        Guid stamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        repo.GetReauthenticationCredentials(accountId, stamp)
            .Returns(new AccountReauthenticationCredentialResult(
                true,
                "FOUND",
                HashPassword(CorrectPassword),
                VerificationStatus.SUCCESSFUL,
                null,
                stamp));

        repo.IssueToken(
                accountId,
                stamp,
                "current-access-hash",
                Arg.Is<string>(value => !string.IsNullOrWhiteSpace(value) && value.Length == 64),
                SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP,
                Arg.Any<Instant>(),
                Arg.Is<Instant>(value => value > now),
                true)
            .Returns(call => new SensitiveActionTokenIssueCommandResult(
                true,
                AccountSensitiveActionService.TokenIssuedCode,
                Guid.NewGuid(),
                call.ArgAt<Instant>(6)));

        SensitiveActionIssueResult result = await service.ReauthenticateAsync(
            new SensitiveActionReauthenticationCommand(
                accountId,
                stamp,
                "current-access-hash",
                CorrectPassword,
                SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP));

        result.Succeeded.ShouldBeTrue();
        result.Result.ShouldBe(HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUED);
        result.Token.ShouldNotBeNullOrWhiteSpace();
        result.Purpose.ShouldBe(SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP);
        result.Expiration.ShouldNotBeNull();
    }

    [Fact]
    public async Task Reauthenticate_does_not_issue_token_when_password_is_wrong()
    {
        var repo = Substitute.For<ISensitiveActionTokenRepo>();
        var service = new AccountSensitiveActionService(repo, Options.Create(new SensitiveActionSettings()));
        Guid accountId = Guid.NewGuid();
        Guid stamp = Guid.NewGuid();

        repo.GetReauthenticationCredentials(accountId, stamp)
            .Returns(new AccountReauthenticationCredentialResult(
                true,
                "FOUND",
                HashPassword(CorrectPassword),
                VerificationStatus.SUCCESSFUL,
                null,
                stamp));

        SensitiveActionIssueResult result = await service.ReauthenticateAsync(
            new SensitiveActionReauthenticationCommand(
                accountId,
                stamp,
                "current-access-hash",
                "wrong-password",
                SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP));

        result.Succeeded.ShouldBeFalse();
        result.Result.ShouldBe(HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED);
        result.Token.ShouldBeNull();
        await repo.DidNotReceive().IssueToken(
            Arg.Any<Guid>(),
            Arg.Any<Guid>(),
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<SensitiveActionPurpose>(),
            Arg.Any<Instant>(),
            Arg.Any<Instant>(),
            Arg.Any<bool>());
    }

    [Fact]
    public async Task Reauthenticate_does_not_issue_token_for_unverified_account()
    {
        var repo = Substitute.For<ISensitiveActionTokenRepo>();
        var service = new AccountSensitiveActionService(repo, Options.Create(new SensitiveActionSettings()));
        Guid accountId = Guid.NewGuid();
        Guid stamp = Guid.NewGuid();

        repo.GetReauthenticationCredentials(accountId, stamp)
            .Returns(new AccountReauthenticationCredentialResult(
                true,
                "FOUND",
                HashPassword(CorrectPassword),
                VerificationStatus.STARTED,
                null,
                stamp));

        SensitiveActionIssueResult result = await service.ReauthenticateAsync(
            new SensitiveActionReauthenticationCommand(
                accountId,
                stamp,
                "current-access-hash",
                CorrectPassword,
                SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP));

        result.Succeeded.ShouldBeFalse();
        result.Result.ShouldBe(HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED);
        await repo.DidNotReceive().IssueToken(
            Arg.Any<Guid>(),
            Arg.Any<Guid>(),
            Arg.Any<string>(),
            Arg.Any<string>(),
            Arg.Any<SensitiveActionPurpose>(),
            Arg.Any<Instant>(),
            Arg.Any<Instant>(),
            Arg.Any<bool>());
    }

    private static byte[] HashPassword(string password)
    {
        return Argon2idPasswordHashCodec.HashToStorageBytes(password, 1, 8192);
    }
}
