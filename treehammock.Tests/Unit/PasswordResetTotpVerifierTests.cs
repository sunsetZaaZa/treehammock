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

public class PasswordResetTotpVerifierTests
{
    [Fact]
    public async Task VerifyTotpForPasswordReset_succeeds_for_valid_shared_enrollment_code_and_step_mark()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret);
        Guid accountId = Guid.NewGuid();
        short twoFactorIndex = 2;
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, twoFactorIndex, protectedSecret, lastUsedStep: null)));
        repo.MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<TotpStepReplayCommandResult?>(new TotpStepReplayCommandResult(true, "TOTP_STEP_ACCEPTED")));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);
        string code = CurrentCode(settings, secret);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, code, CancellationToken.None);

        result.Verified.ShouldBeTrue();
        result.Code.ShouldBe(PasswordResetTotpVerifier.VerifiedCode);
        await repo.Received(1).GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>());
        await repo.Received(1).MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_closed_when_enrollment_is_missing()
    {
        TotpSettings settings = Settings();
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(null));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "123456", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.EnrollmentUnavailableCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_for_managed_provider_until_provider_contract_exists()
    {
        TotpSettings settings = Settings();
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(
                accountId,
                3,
                protectedSecret: null,
                lastUsedStep: null,
                providerType: TotpProviderType.TWILIO_VERIFY_TOTP)));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "123456", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.ProviderUnsupportedCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_closed_when_secret_cannot_be_unprotected()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret);
        byte[] tamperedTag = protectedSecret.Tag.ToArray();
        tamperedTag[0] ^= 0xff;
        protectedSecret = protectedSecret with { Tag = tamperedTag };
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, 1, protectedSecret, lastUsedStep: null)));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "123456", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.SecretUnavailableCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_for_wrong_code_without_marking_step_used()
    {
        TotpSettings settings = Settings();
        byte[] secret = Secret();
        ProtectedTotpSecret protectedSecret = Protect(settings, secret);
        Guid accountId = Guid.NewGuid();
        IAuthenticatorAppEnrollmentRepo repo = Substitute.For<IAuthenticatorAppEnrollmentRepo>();
        repo.GetVerifiedTotpEnrollmentForAccountAsync(accountId, Arg.Any<Instant>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<VerifiedTotpEnrollmentRecord?>(Enrollment(accountId, 1, protectedSecret, lastUsedStep: null)));
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, "000000", CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.IncorrectCode);
        await repo.DidNotReceiveWithAnyArgs().MarkTotpStepUsedAsync(default, default, default, default);
    }

    [Fact]
    public async Task VerifyTotpForPasswordReset_fails_when_shared_step_marking_rejects_replay()
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
        PasswordResetTotpVerifier verifier = Verifier(settings, repo);
        string code = CurrentCode(settings, secret);

        PasswordResetTotpVerificationResult result = await verifier.VerifyTotpForPasswordReset(accountId, code, CancellationToken.None);

        result.Verified.ShouldBeFalse();
        result.Code.ShouldBe(PasswordResetTotpVerifier.ReplayDetectedCode);
        await repo.Received(1).MarkTotpStepUsedAsync(accountId, twoFactorIndex, Arg.Any<long>(), Arg.Any<CancellationToken>());
    }

    private static PasswordResetTotpVerifier Verifier(TotpSettings settings, IAuthenticatorAppEnrollmentRepo repo)
    {
        return new PasswordResetTotpVerifier(
            repo,
            new TotpSecretProtector(Options.Create(settings)),
            new TotpCodeVerifier(Options.Create(settings)),
            NullLogger<PasswordResetTotpVerifier>.Instance);
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
