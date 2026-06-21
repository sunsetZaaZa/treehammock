using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using Npgsql;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Rigging.Database;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;

namespace treehammock.Tests.Unit;

public class RepositoryFailureBoundaryTests
{
    [Fact]
    public async Task Account_repo_returns_controlled_failure_when_connection_open_fails()
    {
        var repo = new AccountRepo(
            new ThrowingStorageContext(),
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        bool? result = true;
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.StartAccountVerification(Guid.NewGuid(), 1);
        });

        exception.ShouldBeNull();
        result.ShouldBeNull();
    }

    [Fact]
    public async Task Account_setup_returns_controlled_creation_failure_when_connection_open_fails()
    {
        var repo = new AccountRepo(
            new ThrowingStorageContext(),
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        (long? verificationIndex, HttpMessage message, string? detail) result = (1, HttpMessage.ACCOUNT_CREATION_SUCCESSED, "unexpected");
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.SetupAccount(null!, "verify-token", Period.FromDays(1), AccountSetupAction.EMAIL);
        });

        exception.ShouldBeNull();
        result.verificationIndex.ShouldBeNull();
        result.message.ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED);
    }

    [Fact]
    public async Task Account_repo_credential_lookup_returns_failed_when_connection_open_fails()
    {
        var repo = new AccountRepo(
            new ThrowingStorageContext(),
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        CredentialLookupResult result = CredentialLookupResult.NotFound();
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.GetCredentials(
                new treehammock.Models.Authentication.AuthenticateLogin("reader@example.com", "Password123!"),
                AccountLoginAction.EMAIL);
        });

        exception.ShouldBeNull();
        result.Status.ShouldBe(CredentialLookupStatus.Failed);
        result.Account.ShouldBeNull();
    }


    [Fact]
    public async Task Account_repo_two_factor_details_lookup_returns_failed_when_connection_open_fails()
    {
        var repo = new AccountRepo(
            new ThrowingStorageContext(),
            Options.Create(new JWTSettings()),
            NullLogger<AccountRepo>.Instance,
            CreateUserSecretHasher());

        TwoFactorDetailsLookupResult result = TwoFactorDetailsLookupResult.NotConfigured();
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.GetTwoFactorDetails(Guid.NewGuid());
        });

        exception.ShouldBeNull();
        result.Status.ShouldBe(TwoFactorDetailsLookupStatus.Failed);
        result.Details.ShouldBeNull();
    }

    [Fact]
    public async Task Session_repo_returns_controlled_failure_when_connection_open_fails()
    {
        var repo = new SessionRepo(
            new ThrowingStorageContext(),
            Options.Create(new JWTSettings()),
            NullLogger<SessionRepo>.Instance);

        bool? result = true;
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.ExpireSession("old-access-token-hash", SystemClock.Instance.GetCurrentInstant());
        });

        exception.ShouldBeNull();
        result.ShouldBeNull();
    }

    [Fact]
    public async Task Account_recovery_repo_returns_controlled_failure_when_connection_open_fails()
    {
        var repo = new AccountRecoveryRepo(
            new ThrowingStorageContext(),
            NullLogger<AccountRecoveryRepo>.Instance);

        AccountRecovery_Status? result = AccountRecovery_Status.STARTED;
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.VerifyUnlock("recovery-token");
        });

        exception.ShouldBeNull();
        result.ShouldBeNull();
    }

    [Fact]
    public async Task Activation_repo_returns_controlled_failure_when_connection_open_fails()
    {
        var repo = new ActivationRepo(
            new ThrowingStorageContext(),
            NullLogger<ActivationRepo>.Instance);

        treehammock.DataLayer.ActivationCommandResult? result = new treehammock.DataLayer.ActivationCommandResult(true, "unexpected", ActivationStatus.REQUEST);
        Exception? exception = await Record.ExceptionAsync(async () =>
        {
            result = await repo.DisableActivation(
                Guid.NewGuid(),
                Guid.NewGuid(),
                "reader@example.com",
                SystemClock.Instance.GetCurrentInstant(),
                SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromDays(1)),
                ActivationStatus.DISRUPTED);
        });

        exception.ShouldBeNull();
        result.ShouldBeNull();
    }


    [Theory]
    [InlineData("reader@example.com", "email", 18)]
    [InlineData("+15555550123", "phone", 12)]
    [InlineData("reader", "username", 6)]
    [InlineData("", "blank", 0)]
    public void Repository_identifier_log_scope_carries_metadata_without_identifier_value(
        string identifier,
        string expectedKind,
        int expectedLength)
    {
        RepositorySensitiveValueLogScope scope = RepositoryLogScopes.Identifier(identifier);

        scope.ValueKind.ShouldBe(expectedKind);
        scope.ValueLength.ShouldBe(expectedLength);
        scope.ValueFingerprint.ShouldNotBeNullOrWhiteSpace();

        if (!string.IsNullOrEmpty(identifier))
        {
            scope.ToString().ShouldNotContain(identifier);
        }
    }

    [Fact]
    public void Repository_failure_scopes_do_not_capture_raw_user_identifiers()
    {
        string reposRoot = ProjectFile("Repos");
        string[] repositoryFiles =
        {
            Path.Combine(reposRoot, "AccountRepo.cs"),
            Path.Combine(reposRoot, "AccountRecoveryRepo.cs"),
            Path.Combine(reposRoot, "ActivationRepo.cs"),
            Path.Combine(reposRoot, "SessionRepo.cs")
        };

        string[] forbiddenRawScopeFragments =
        {
            "new { step, single.accountId, single.emailAddress, single.username",
            "new { identifier,",
            "new { emailAddress",
            "new { accountId, emailAddress",
            "new { accountId, username",
            "new { accountId, newEmailAddress",
            "new { tokenHash",
            "new { accessTokenHash",
            "new { accountId, accessTokenHash",
            "new { accountId, expectedOldAccessTokenHash",
            "new { accountId, newAccessTokenHash"
        };

        foreach (string repositoryFile in repositoryFiles)
        {
            string text = File.ReadAllText(repositoryFile);

            foreach (string fragment in forbiddenRawScopeFragments)
            {
                text.Contains(fragment, StringComparison.Ordinal).ShouldBeFalse($"{Path.GetFileName(repositoryFile)} should use RepositoryLogScopes metadata instead of raw failure scope values.");
            }
        }
    }

    private sealed class ThrowingStorageContext : StorageContext
    {
        public ThrowingStorageContext()
            : base(Options.Create(new DatabaseSettings
            {
                servers = "localhost",
                database = "treehammock_tests",
                userId = "treehammock",
                password = "test-password",
                lc_collation = "en_US.UTF-8"
            }))
        {
        }

        public override Task<NpgsqlConnection> CreateConnection()
        {
            throw new InvalidOperationException("Simulated connection-open failure.");
        }
    }


    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }

    private static IUserSecretHasher CreateUserSecretHasher()
    {
        return new Argon2idUserSecretHasher(Options.Create(new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            Argon2Iterations = 1,
            Argon2MemoryUsePer = 8192,
            TwoFactorChallengePepper = "0123456789abcdef"
        }));
    }

}
