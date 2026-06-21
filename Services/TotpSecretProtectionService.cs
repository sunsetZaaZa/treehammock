using System.Security.Cryptography;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;

namespace treehammock.Services;

public interface ITotpSecretProtector
{
    ProtectedTotpSecret Protect(byte[] secret);

    byte[] Unprotect(ProtectedTotpSecret protectedSecret);
}

public sealed record ProtectedTotpSecret(
    byte[] Ciphertext,
    byte[] Nonce,
    byte[] Tag,
    int Version);

public sealed class TotpSecretProtector : ITotpSecretProtector
{
    public const int CurrentVersion = 1;
    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;

    private static readonly byte[] AssociatedData = "treehammock:totp-secret:v1"u8.ToArray();

    private readonly IOptions<TotpSettings> _settings;

    public TotpSecretProtector(IOptions<TotpSettings> settings)
    {
        _settings = settings;
    }

    public ProtectedTotpSecret Protect(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
        {
            throw new ArgumentException("TOTP secret cannot be empty.", nameof(secret));
        }

        byte[] key = ProtectionKey();
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSizeBytes);
        byte[] ciphertext = new byte[secret.Length];
        byte[] tag = new byte[TagSizeBytes];

        try
        {
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Encrypt(nonce, secret, ciphertext, tag, AssociatedData);
            return new ProtectedTotpSecret(ciphertext, nonce, tag, CurrentVersion);
        }
        finally
        {
            Array.Clear(key);
        }
    }

    public byte[] Unprotect(ProtectedTotpSecret protectedSecret)
    {
        ArgumentNullException.ThrowIfNull(protectedSecret);
        if (protectedSecret.Version != CurrentVersion)
        {
            throw new InvalidOperationException("Unsupported protected TOTP secret version.");
        }

        if (protectedSecret.Nonce.Length != NonceSizeBytes)
        {
            throw new InvalidOperationException("Protected TOTP secret nonce is invalid.");
        }

        if (protectedSecret.Tag.Length != TagSizeBytes)
        {
            throw new InvalidOperationException("Protected TOTP secret tag is invalid.");
        }

        if (protectedSecret.Ciphertext.Length == 0)
        {
            throw new InvalidOperationException("Protected TOTP secret ciphertext is empty.");
        }

        byte[] key = ProtectionKey();
        byte[] secret = new byte[protectedSecret.Ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSizeBytes);
            aes.Decrypt(protectedSecret.Nonce, protectedSecret.Ciphertext, protectedSecret.Tag, secret, AssociatedData);
            return secret;
        }
        finally
        {
            Array.Clear(key);
        }
    }

    private byte[] ProtectionKey()
    {
        if (!TotpSettings.TryDecodeProtectionKey(_settings.Value.SecretProtectionKey, out byte[] key))
        {
            throw new InvalidOperationException($"TotpSettings:SecretProtectionKey must be a base64-encoded {TotpSettings.RequiredProtectionKeyBytes}-byte key.");
        }

        return key;
    }
}
