using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class TotpSecretProtectionServiceTests
{
    [Fact]
    public void Protect_returns_ciphertext_nonce_tag_and_version_without_plaintext_storage()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        byte[] secret = [1, 2, 3, 4, 5, 6, 7, 8];

        ProtectedTotpSecret protectedSecret = protector.Protect(secret);

        protectedSecret.Version.ShouldBe(TotpSecretProtector.CurrentVersion);
        protectedSecret.Nonce.Length.ShouldBe(TotpSecretProtector.NonceSizeBytes);
        protectedSecret.Tag.Length.ShouldBe(TotpSecretProtector.TagSizeBytes);
        protectedSecret.Ciphertext.Length.ShouldBe(secret.Length);
        protectedSecret.Ciphertext.ShouldNotBe(secret);
    }

    [Fact]
    public void Unprotect_round_trips_secret()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        byte[] secret = [10, 20, 30, 40, 50, 60];

        ProtectedTotpSecret protectedSecret = protector.Protect(secret);
        byte[] unprotected = protector.Unprotect(protectedSecret);

        unprotected.ShouldBe(secret);
    }

    [Fact]
    public void Unprotect_fails_closed_when_ciphertext_is_tampered()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        ProtectedTotpSecret protectedSecret = protector.Protect([1, 2, 3, 4]);
        protectedSecret.Ciphertext[0] ^= 0x01;

        Should.Throw<CryptographicException>(() => protector.Unprotect(protectedSecret));
    }

    [Fact]
    public void Unprotect_fails_closed_when_secret_version_is_unknown()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings()));
        ProtectedTotpSecret protectedSecret = protector.Protect([1, 2, 3, 4]);
        var wrongVersion = protectedSecret with { Version = 999 };

        Should.Throw<InvalidOperationException>(() => protector.Unprotect(wrongVersion));
    }

    [Fact]
    public void Protector_requires_valid_base64_32_byte_key()
    {
        var protector = new TotpSecretProtector(Options.Create(Settings(secretProtectionKey: "not-base64")));

        Should.Throw<InvalidOperationException>(() => protector.Protect([1, 2, 3, 4]));
    }

    private static TotpSettings Settings(string secretProtectionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    {
        return new TotpSettings
        {
            Issuer = "Treehammock",
            Digits = 6,
            PeriodSeconds = 30,
            AllowedClockSkewSteps = 1,
            HashAlgorithm = "SHA1",
            SecretBytes = 20,
            SecretProtectionKey = secretProtectionKey
        };
    }
}
