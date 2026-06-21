using Microsoft.Extensions.Options;

using treehammock.Rigging.Config;

namespace treehammock.Rigging.Security;

public interface IUserSecretHasher
{
    string HashUserSecret(string secret);
    bool VerifyUserSecret(string secret, string storedHash);
}

public sealed class Argon2idUserSecretHasher : IUserSecretHasher
{
    private readonly LoginSettings _loginSettings;

    public Argon2idUserSecretHasher(IOptions<LoginSettings> loginSettings)
    {
        _loginSettings = loginSettings.Value;
    }

    public string HashUserSecret(string secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new ArgumentException("A non-empty user secret is required.", nameof(secret));
        }

        return Argon2idPasswordHashCodec.HashToStorageString(
            secret,
            _loginSettings.Argon2Iterations,
            _loginSettings.Argon2MemoryUsePer);
    }

    public bool VerifyUserSecret(string secret, string storedHash)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        try
        {
            return Argon2idPasswordHashCodec.VerifyStorageString(storedHash, secret);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
