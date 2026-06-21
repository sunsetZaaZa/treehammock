using System.Text;

using Microsoft.Extensions.Options;
using NodaTime;

using treehammock.DataLayer.Security;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Services;

public sealed record SensitiveActionReauthenticationCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SessionBindingHash,
    string Password,
    SensitiveActionPurpose Purpose);

public sealed record SensitiveActionIssueResult(
    bool Succeeded,
    HttpMessage Result,
    string Code,
    string? Token = null,
    SensitiveActionPurpose? Purpose = null,
    Instant? Expiration = null);

public sealed record SensitiveActionValidationCommand(
    Guid AccountId,
    Guid AccountSecurityStamp,
    string SessionBindingHash,
    string Token,
    SensitiveActionPurpose Purpose,
    bool Consume = true);

public sealed record SensitiveActionValidationResult(
    bool Succeeded,
    HttpMessage Result,
    string Code,
    SensitiveActionPurpose? Purpose = null,
    Instant? Expiration = null);

public interface IAccountSensitiveActionService
{
    Task<SensitiveActionIssueResult> ReauthenticateAsync(
        SensitiveActionReauthenticationCommand command,
        CancellationToken cancellationToken = default);

    Task<SensitiveActionValidationResult> ValidateAsync(
        SensitiveActionValidationCommand command,
        CancellationToken cancellationToken = default);
}

public sealed class AccountSensitiveActionService : IAccountSensitiveActionService
{
    public const string TokenIssuedCode = "SENSITIVE_ACTION_TOKEN_ISSUED";
    public const string InvalidPurposeCode = "SENSITIVE_ACTION_INVALID_PURPOSE";
    public const string ReauthenticationFailedCode = "SENSITIVE_ACTION_REAUTHENTICATION_FAILED";
    public const string TokenIssueFailedCode = "SENSITIVE_ACTION_TOKEN_ISSUE_FAILED";
    public const string TokenValidatedCode = "SENSITIVE_ACTION_TOKEN_VALIDATED";
    public const string TokenValidationFailedCode = "SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED";

    private readonly ISensitiveActionTokenRepo _sensitiveActionTokenRepo;
    private readonly SensitiveActionSettings _settings;

    public AccountSensitiveActionService(
        ISensitiveActionTokenRepo sensitiveActionTokenRepo,
        IOptions<SensitiveActionSettings> settings)
    {
        _sensitiveActionTokenRepo = sensitiveActionTokenRepo;
        _settings = settings.Value;
    }

    public async Task<SensitiveActionIssueResult> ReauthenticateAsync(
        SensitiveActionReauthenticationCommand command,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsSupportedPurpose(command.Purpose))
        {
            return new SensitiveActionIssueResult(
                false,
                HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUE_FAILED,
                InvalidPurposeCode);
        }

        if (string.IsNullOrWhiteSpace(command.Password) || string.IsNullOrWhiteSpace(command.SessionBindingHash))
        {
            return FailedReauthentication();
        }

        AccountReauthenticationCredentialResult? credentials = await _sensitiveActionTokenRepo.GetReauthenticationCredentials(
            command.AccountId,
            command.AccountSecurityStamp);

        if (credentials?.Result != true || credentials.HashedPassword is null)
        {
            return FailedReauthentication();
        }

        if (credentials.VerificationStatus != VerificationStatus.SUCCESSFUL)
        {
            return FailedReauthentication();
        }

        Instant now = SystemClock.Instance.GetCurrentInstant();
        if (credentials.CutOff is not null && credentials.CutOff.Value <= now)
        {
            return FailedReauthentication();
        }

        bool passwordVerified = Argon2idPasswordHashCodec.VerifyStorageBytes(
            credentials.HashedPassword,
            command.Password);

        if (!passwordVerified)
        {
            return FailedReauthentication();
        }

        string token = AccountVerificationTokenUtility.GenerateToken(_settings.TokenBytes);
        string tokenHash = AccountVerificationTokenUtility.HashToken(token);
        Instant expiration = now.Plus(Duration.FromMinutes(_settings.ExpirationMinutes));

        SensitiveActionTokenIssueCommandResult? issue = await _sensitiveActionTokenRepo.IssueToken(
            command.AccountId,
            command.AccountSecurityStamp,
            command.SessionBindingHash,
            tokenHash,
            command.Purpose,
            now,
            expiration,
            _settings.ConsumeExistingTokensOnIssue);

        if (issue?.Result != true || issue.Expiration is null)
        {
            return new SensitiveActionIssueResult(
                false,
                HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUE_FAILED,
                issue?.Code ?? TokenIssueFailedCode);
        }

        return new SensitiveActionIssueResult(
            true,
            HttpMessage.SENSITIVE_ACTION_TOKEN_ISSUED,
            string.IsNullOrWhiteSpace(issue.Code) ? TokenIssuedCode : issue.Code,
            token,
            command.Purpose,
            issue.Expiration);
    }


    public async Task<SensitiveActionValidationResult> ValidateAsync(
        SensitiveActionValidationCommand command,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!IsSupportedPurpose(command.Purpose))
        {
            return FailedValidation(InvalidPurposeCode);
        }

        if (string.IsNullOrWhiteSpace(command.Token) || string.IsNullOrWhiteSpace(command.SessionBindingHash))
        {
            return FailedValidation(TokenValidationFailedCode);
        }

        string tokenHash = AccountVerificationTokenUtility.HashToken(command.Token);
        SensitiveActionTokenValidationCommandResult? validation = await _sensitiveActionTokenRepo.ValidateToken(
            command.AccountId,
            command.AccountSecurityStamp,
            command.SessionBindingHash,
            tokenHash,
            command.Purpose,
            command.Consume,
            SystemClock.Instance.GetCurrentInstant());

        if (validation?.Result != true)
        {
            return FailedValidation(validation?.Code ?? TokenValidationFailedCode);
        }

        return new SensitiveActionValidationResult(
            true,
            HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATED,
            string.IsNullOrWhiteSpace(validation.Code) ? TokenValidatedCode : validation.Code,
            command.Purpose,
            validation.Expiration);
    }

    private static bool IsSupportedPurpose(SensitiveActionPurpose purpose)
    {
        return purpose is SensitiveActionPurpose.TWO_FACTOR_AUTHENTICATOR_SETUP
            or SensitiveActionPurpose.TWO_FACTOR_METHOD_REMOVE;
    }

    private static SensitiveActionIssueResult FailedReauthentication()
    {
        return new SensitiveActionIssueResult(
            false,
            HttpMessage.SENSITIVE_ACTION_REAUTHENTICATION_FAILED,
            ReauthenticationFailedCode);
    }

    private static SensitiveActionValidationResult FailedValidation(string code)
    {
        return new SensitiveActionValidationResult(
            false,
            HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATION_FAILED,
            string.IsNullOrWhiteSpace(code) ? TokenValidationFailedCode : code);
    }
}
