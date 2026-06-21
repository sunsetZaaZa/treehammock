using System.Security.Cryptography;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;
using treehammock.Rigging.Security;

namespace treehammock.Services;

public interface IPasswordResetPasswordMaterialFactory
{
    PasswordResetPasswordMaterial CreatePasswordMaterial(string password);
}

public sealed record PasswordResetPasswordMaterial(
    byte[] HashedPassword,
    byte[] SaltOne,
    byte[] Siv,
    byte[] Nonce);

public sealed class PasswordResetPasswordMaterialFactory : IPasswordResetPasswordMaterialFactory
{
    private const int SaltOffset = 0;
    private const int SivOffset = SaltOffset + AccountCryptoSizes.SaltOneBytes;
    private const int NonceOffset = SivOffset + AccountCryptoSizes.SivBytes;
    private const int RandomMaterialBytes = AccountCryptoSizes.SaltOneBytes + AccountCryptoSizes.SivBytes + AccountCryptoSizes.NonceBytes;

    private readonly LoginSettings _loginSettings;

    public PasswordResetPasswordMaterialFactory(IOptions<LoginSettings> loginSettings)
    {
        _loginSettings = loginSettings.Value;
    }

    public PasswordResetPasswordMaterial CreatePasswordMaterial(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("A non-empty password is required.", nameof(password));
        }

        byte[] passwordHash = Argon2idPasswordHashCodec.HashToStorageBytes(
            password,
            _loginSettings.Argon2Iterations,
            _loginSettings.Argon2MemoryUsePer);

        byte[] randomMaterial = RandomNumberGenerator.GetBytes(RandomMaterialBytes);

        return new PasswordResetPasswordMaterial(
            passwordHash,
            Slice(randomMaterial, AccountCryptoSizes.SaltOneBytes, SaltOffset),
            Slice(randomMaterial, AccountCryptoSizes.SivBytes, SivOffset),
            Slice(randomMaterial, AccountCryptoSizes.NonceBytes, NonceOffset));
    }

    private static byte[] Slice(byte[] source, int length, int offset)
    {
        byte[] result = new byte[length];
        Buffer.BlockCopy(source, offset, result, 0, length);
        return result;
    }
}
