using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;

using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Security;
using treehammock.Rigging.Replay;
using treehammock.Rigging.Health;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class DependencyInjectionRegistrationTests
{
    [Theory]
    [InlineData(typeof(IActiveUserCacheService), typeof(ActiveUserCacheService))]
    [InlineData(typeof(IAbuseCounterStore), typeof(DragonflyAbuseCounterStore))]
    [InlineData(typeof(IDeliveryAbuseThrottleService), typeof(DeliveryAbuseThrottleService))]
    [InlineData(typeof(IAuthenticatedMutationIdempotencyService), typeof(DragonflyAuthenticatedMutationIdempotencyService))]
    [InlineData(typeof(IHealthDependencyService), typeof(HealthDependencyService))]
    [InlineData(typeof(ILoginAbuseCounterKeyFactory), typeof(LoginAbuseCounterKeyFactory))]
    [InlineData(typeof(ITwoFactorSessionService), typeof(TwoFactorSessionService))]
    [InlineData(typeof(IPasswordResetSessionService), typeof(PasswordResetSessionService))]
    [InlineData(typeof(IJsonWebTokenUtility), typeof(JsonWebTokenUtility))]
    [InlineData(typeof(IUserSecretHasher), typeof(Argon2idUserSecretHasher))]
    [InlineData(typeof(IAccountService), typeof(AccountService))]
    [InlineData(typeof(IActivationService), typeof(ActivationService))]
    [InlineData(typeof(IPasswordResetService), typeof(PasswordResetService))]
    [InlineData(typeof(IPasswordResetCodeGenerator), typeof(PasswordResetCodeGenerator))]
    [InlineData(typeof(IPasswordResetCodeHasher), typeof(PasswordResetCodeHasher))]
    [InlineData(typeof(IPasswordResetRateLimitKeyFactory), typeof(PasswordResetRateLimitKeyFactory))]
    [InlineData(typeof(IPasswordResetAbuseCounterKeyFactory), typeof(PasswordResetAbuseCounterKeyFactory))]
    [InlineData(typeof(IAccountUnlockAbuseCounterKeyFactory), typeof(AccountUnlockAbuseCounterKeyFactory))]
    [InlineData(typeof(IAccountTokenVerificationAbuseCounterKeyFactory), typeof(AccountTokenVerificationAbuseCounterKeyFactory))]
    [InlineData(typeof(IActivationAbuseCounterKeyFactory), typeof(ActivationAbuseCounterKeyFactory))]
    [InlineData(typeof(IPasswordResetAbusePolicy), typeof(PasswordResetAbusePolicy))]
    [InlineData(typeof(IPasswordResetDeliveryService), typeof(PasswordResetDeliveryService))]
    [InlineData(typeof(IPasswordResetTotpVerifier), typeof(PasswordResetTotpVerifier))]
    [InlineData(typeof(IPasswordResetPasswordMaterialFactory), typeof(PasswordResetPasswordMaterialFactory))]
    [InlineData(typeof(ITotpSecretProtector), typeof(TotpSecretProtector))]
    [InlineData(typeof(ITotpCodeVerifier), typeof(TotpCodeVerifier))]
    [InlineData(typeof(IAuthenticatorAppSecretGenerator), typeof(AuthenticatorAppSecretGenerator))]
    [InlineData(typeof(IAuthenticatorAppBase32Encoder), typeof(AuthenticatorAppBase32Encoder))]
    [InlineData(typeof(IAuthenticatorAppProvisioningUriBuilder), typeof(AuthenticatorAppProvisioningUriBuilder))]
    [InlineData(typeof(ITotpProvider), typeof(LocalTotpProvider))]
    [InlineData(typeof(ITotpProviderRegistry), typeof(TotpProviderRegistry))]
    [InlineData(typeof(IAccountRecoveryService), typeof(AccountRecoveryService))]
    [InlineData(typeof(ITwoFactorAuthenticateService), typeof(TwoFactorAuthenticateService))]
    [InlineData(typeof(ISMTPService), typeof(SMTPService))]
    [InlineData(typeof(IAwsSnsSmsClient), typeof(AwsSnsSmsClient))]
    [InlineData(typeof(IAWSService), typeof(AWSService))]
    [InlineData(typeof(ITwilioMessageClient), typeof(TwilioMessageClient))]
    [InlineData(typeof(ITwilioSmsService), typeof(TwilioSmsService))]
    [InlineData(typeof(ISmsSender), typeof(SmsSender))]
    [InlineData(typeof(IAccountRepo), typeof(AccountRepo))]
    [InlineData(typeof(IAccountRecoveryRepo), typeof(AccountRecoveryRepo))]
    [InlineData(typeof(IActivationRepo), typeof(ActivationRepo))]
    [InlineData(typeof(ISessionRepo), typeof(SessionRepo))]
    [InlineData(typeof(IPasswordResetRepo), typeof(PasswordResetRepo))]
    [InlineData(typeof(IPasswordResetTotpRepo), typeof(PasswordResetTotpRepo))]
    [InlineData(typeof(ISensitiveActionTokenRepo), typeof(SensitiveActionTokenRepo))]
    [InlineData(typeof(IAuthenticatorAppEnrollmentRepo), typeof(AuthenticatorAppEnrollmentRepo))]
    [InlineData(typeof(IAccountSensitiveActionService), typeof(AccountSensitiveActionService))]
    [InlineData(typeof(IAuthenticatorAppSetupService), typeof(AuthenticatorAppSetupService))]
    [InlineData(typeof(IAuthenticatorAppLoginVerifier), typeof(AuthenticatorAppLoginVerifier))]
    public void AddTreehammockServices_registers_interfaces_as_singletons(Type serviceType, Type implementationType)
    {
        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(TestConfiguration.ValidSettings())
            .Build();

        services.AddTreehammockServices(configuration);

        services.ShouldContain(descriptor =>
            descriptor.ServiceType == serviceType &&
            descriptor.ImplementationType == implementationType &&
            descriptor.Lifetime == ServiceLifetime.Singleton);
    }

    [Fact]
    public void AddTreehammockServices_does_not_register_unsupported_provider_surfaces()
    {
        var services = new ServiceCollection();
        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(TestConfiguration.ValidSettings())
            .Build();

        services.AddTreehammockServices(configuration);

        string[] unsupportedProviderTypeNames =
        [
            "IEmailService",
            "EmailService",
            "I" + "Au" + "thy" + "Service",
            "Au" + "thy" + "Service",
            "IGoogleAuthenticatorService",
            "GoogleAuthenticatorService",
            "IAlphabetService",
            "AlphabetService",
            "IOAuthService",
            "OAuthService",
            "IPushNotificationService",
            "PushNotificationService"
        ];

        foreach (string typeName in unsupportedProviderTypeNames)
        {
            services.Any(descriptor =>
            {
                Type? implementationType = descriptor.ImplementationType;
                return descriptor.ServiceType.Name == typeName ||
                    (implementationType != null && implementationType.Name == typeName);
            }).ShouldBeFalse($"Unsupported provider type '{typeName}' should not be registered.");
        }
    }

    [Fact]
    public void Unsupported_provider_source_files_are_not_part_of_the_active_project()
    {
        string root = ProjectRoot();

        File.Exists(Path.Combine(root, "Rigging", "EmailService.cs")).ShouldBeFalse();
        File.Exists(Path.Combine(root, "Rigging", "Sidewalk", "AlphabetService.cs")).ShouldBeFalse();
        File.Exists(Path.Combine(root, "Rigging", "Sidewalk", "OAuthService.cs")).ShouldBeFalse();
        File.Exists(Path.Combine(root, "Services", "PushNotificationService.cs")).ShouldBeFalse();
    }

    [Fact]
    public void Unsupported_oauth_packages_are_not_referenced_by_the_app_project()
    {
        string project = File.ReadAllText(ProjectFile("treehammock.csproj"));

        project.ShouldNotContain("Microsoft.Owin.Security.OAuth");
        project.ShouldNotContain("OAuth.DotNetCore");
    }

    [Fact]
    public void Program_registers_jwt_middleware_before_controller_mapping_without_framework_authorization_middleware()
    {
        string program = File.ReadAllText(ProjectFile("Program.cs"));

        int middlewareIndex = program.IndexOf("app.UseMiddleware<JsonWebTokenMiddleware>();", StringComparison.Ordinal);
        int mapControllersIndex = program.IndexOf("app.MapControllers();", StringComparison.Ordinal);

        middlewareIndex.ShouldBeGreaterThan(-1);
        mapControllersIndex.ShouldBeGreaterThan(-1);
        program.ShouldNotContain("app.UseAuthorization();");
        program.ShouldNotContain("services.AddAuthorization");
        middlewareIndex.ShouldBeLessThan(mapControllersIndex);
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

    private static string ProjectFile(string relativePath)
    {
        return Path.Combine(ProjectRoot(), relativePath);
    }
}
