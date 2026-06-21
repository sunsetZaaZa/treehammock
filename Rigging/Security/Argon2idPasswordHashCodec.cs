using System.Text;

using Geralt;

namespace treehammock.Rigging.Security;

public static class Argon2idPasswordHashCodec
{
    public static byte[] HashToStorageBytes(string secret, int iterations, int memorySize)
    {
        char[] hash = new char[AccountCryptoSizes.PasswordHashBytes];
        Argon2id.ComputeHash(hash, Encoding.UTF8.GetBytes(secret), iterations, memorySize);
        return Encoding.UTF8.GetBytes(new string(hash));
    }

    public static string HashToStorageString(string secret, int iterations, int memorySize)
    {
        char[] hash = new char[AccountCryptoSizes.PasswordHashBytes];
        Argon2id.ComputeHash(hash, Encoding.UTF8.GetBytes(secret), iterations, memorySize);
        return new string(hash).TrimEnd('\0');
    }

    public static bool VerifyStorageBytes(byte[] storedHash, string secret)
    {
        if (storedHash.Length == 0 || string.IsNullOrEmpty(secret))
        {
            return false;
        }

        string encodedHash = Encoding.UTF8.GetString(storedHash).TrimEnd('\0');
        return Argon2id.VerifyHash(encodedHash.AsSpan(), Encoding.UTF8.GetBytes(secret));
    }

    public static bool VerifyStorageString(string storedHash, string secret)
    {
        if (string.IsNullOrWhiteSpace(storedHash) || string.IsNullOrEmpty(secret))
        {
            return false;
        }

        return Argon2id.VerifyHash(storedHash.AsSpan(), Encoding.UTF8.GetBytes(secret));
    }
}
