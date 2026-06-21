using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AuthenticatorAppLoginVerifierTests
{
    [Fact]
    public async Task VerifyForLogin_succeeds_for_valid_local_enrollment_code_and_marks_step_used()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret);
        Guid accountId = Guid.NewGuid();
        short twoFactorIndex = 7;
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, twoFactorIndex, protectedSecret, lastUsedStep: null)));
        repo.MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<TotpStepReplayCommandResult?>(new TotpStepReplayCommandResult(true, "TOTP_STEP_ACCEPTED")));
        AuthenticatorAppLoginVerifier verifier = Verifier(settings, repo);
        string code = CurrentCode(settings, secret);

        AuthenticatorAppLoginVerificationResult result = await verifier.VerifyForLoginAsync(accountId, code, SystemClock.Instance.GetCurrentInstant());

        result.Verified.ShouldBeTrue();
        result.Code.ShouldBe(AuthenticatorAppLoginVerifier.VerifiedCode);
        await repo.Received(1).MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyForLogin_fails_closed_when_enrollment_is_missing()
    {
        TotpSettings settings = Settings();
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(null));
        AuthenticatorAppLoginVerifier verifier = Verifier(settings, repo);

        AuthenticatorAppLoginVerificationResult result = await verifier.VerifyForLoginAsync(accountId, "123456", SystemClock.Instance.GetCurrentInstant());

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(AuthenticatorAppLoginVerifier.EnrollmentUnavailableCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default);
    }

    [Fact]
    public async Task VerifyForLogin_fails_for_managed_provider_until_provider_contract_exists()
    {
        TotpSettings settings = Settings();
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(
                accountId,
                2,
                protectedSecret: null,
                lastUsedStep: null,
                providerType: TotpProviderType.TWILIO_VERIFY_TOTP)));
        AuthenticatorAppLoginVerifier verifier = Verifier(settings, repo);

        AuthenticatorAppLoginVerificationResult result = await verifier.VerifyForLoginAsync(accountId, "123456", SystemClock.Instance.GetCurrentInstant());

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(AuthenticatorAppLoginVerifier.ProviderUnsupportedCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default);
    }

    [Fact]
    public async Task VerifyForLogin_fails_for_wrong_code_without_marking_step_used()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret);
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, 1, protectedSecret, lastUsedStep: null)));
        AuthenticatorAppLoginVerifier verifier = Verifier(settings, repo);

        AuthenticatorAppLoginVerificationResult result = await verifier.VerifyForLoginAsync(accountId, "000000", SystemClock.Instance.GetCurrentInstant());

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(AuthenticatorAppLoginVerifier.IncorrectCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default);
    }

    [Fact]
    public async Task VerifyForLogin_fails_when_step_marking_rejects_replay()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret);
        Guid accountId = Guid.NewGuid();
        short twoFactorIndex = 4;
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, twoFactorIndex, protectedSecret, lastUsedStep: null)));
        repo.MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<TotpStepReplayCommandResult?>(new TotpStepReplayCommandResult(false, "TOTP_REPLAY_DETECTED")));
        AuthenticatorAppLoginVerifier verifier = Verifier(settings, repo);
        string code = CurrentCode(settings, secret);

        AuthenticatorAppLoginVerificationResult result = await verifier.VerifyForLoginAsync(accountId, code, SystemClock.Instance.GetCurrentInstant());

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(AuthenticatorAppLoginVerifier.ReplayDetectedCode);
        await repo.Received(1).MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<CancellationToken>());
    }

    private static AuthenticatorAppLoginVerifier Verifier(TotpSettings settings, IAuthenticatorAppEnrollmentRepo repo)
    {
        return new AuthenticatorAppLoginVerifier(
            repo,
            new TotpSecretProtector(Options.Create(settings)),
            new TotpCodeVerifier(Options.Create(settings)),
            NullLogger<AuthenticatorAppLoginVerifier>.Instance);
    }

    private static VerifiedTotpEnrollmentRecord Enrollment(
        Guid accountId,
        short twoFactorIndex,
        ProtectedTotpSecret? protectedSecret,
        long? lastUsedStep,
        TotpProviderType providerType = TotpProviderType.LOCAL_RFC6238)
    {
        return new VerifiedTotpEnrollmentRecord(
            accountId,
            twoFactorIndex,
            3,
            (short)providerType,
            providerType == TotpProviderType.TWILIO_VERIFY_TOTP ? "managed-enrollment" : null,
            providerType == TotpProviderType.TWILIO_VERIFY_TOTP ? "binding-hash" : null,
            protectedSecret?.Ciphertext,
            protectedSecret?.Nonce,
            protectedSecret?.Tag,
            protectedSecret?.Version,
            lastUsedStep);
    }

    private static ProtectedTotpSecret Protect(TotpSettings settings, byte[] secret)
    {
        return new TotpSecretProtector(Options.Create(settings)).Protect(secret);
    }

    private static string CurrentCode(TotpSettings settings, byte[] secret)
    {
        Instant now = SystemClock.Instance.GetCurrentInstant();
        long step = now.ToUnixTimeSeconds() / settings.PeriodSeconds;
        return TotpCodeVerifier.ComputeCode(secret, step, settings.Digits, settings.HashAlgorithm);
    }

    private static byte[] Secret()
    {
        return "12345678901234567890"u8.ToArray();
    }

    private static TotpSettings Settings()
    {
        return new TotpSettings
        {
            Issuer = "Treehammock",
            Digits = 6,
            PeriodSeconds = 30,
            AllowedClockSkewSteps = 1,
            HashAlgorithm = "SHA1",
            SecretBytes = 20,
            SecretProtectionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
            SetupIdBytes = 32,
            SetupExpirationMinutes = 10,
            SetupMaxAttempts = 5
        };
    }
}
