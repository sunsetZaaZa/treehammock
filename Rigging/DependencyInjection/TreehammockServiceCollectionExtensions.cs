using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Provider;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;
using treehammock.Services.SystemTesting;
using treehammock.Rigging.Security;
using treehammock.Rigging.Replay;
using treehammock.Rigging.Health;

namespace treehammock.Rigging.DependencyInjection;

public static class TreehammockServiceCollectionExtensions
{
    public static IServiceCollection AddTreehammockServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.AddHttpClient();

        services.AddValidatedOptions<DatabaseSettings>(configuration, "DatabaseSettings");
        services.AddValidatedOptions<UserCacheSettings>(configuration, "ActiveUserBundleSettings");
        services.AddValidatedOptions<TwoFactorSessionCacheSettings>(configuration, "TwoFactorSessionBundleSettings");
        services.AddValidatedOptions<AbuseCounterCacheSettings>(configuration, "AbuseCounterBundleSettings");
        services.AddValidatedOptions<SessionCacheFallbackSettings>(configuration, "SessionCacheFallbackSettings");
        services.AddValidatedOptions<AbuseControlSettings>(configuration, "AbuseControlSettings");
        services.AddValidatedOptions<JWTSettings>(configuration, "JWTSettings");
        services.AddValidatedOptions<LoginSettings>(configuration, "LoginSettings");
        services.AddValidatedOptions<RegistrationSettings>(configuration, "RegistrationSettings");
        services.AddValidatedOptions<PasswordResetSettings>(configuration, "PasswordResetSettings");
        services.AddValidatedOptions<SensitiveActionSettings>(configuration, "SensitiveActionSettings");
        services.AddValidatedOptions<TotpSettings>(configuration, "TotpSettings");
        services.AddValidatedOptions<SMTPSettings>(configuration, "SMTPSettings");
        services.AddValidatedOptions<EmailTemplateSettings>(configuration, "EmailTemplateSettings");
        services.AddValidatedOptions<EmailSubjectSettings>(configuration, "EmailSubjectSettings");
        services.AddValidatedOptions<SidewalkSettings>(configuration, "SidewalkSettings");
        services.AddValidatedOptions<HostingSettings>(configuration, "HostingSettings");
        services.Configure<SystemTestSettings>(configuration.GetSection("SystemTestSettings"));

        // 1.0.0 uses StorageContext as the PostgreSQL contract owner for account, session, and password-reset rows.
        // A dedicated SessionContext or split database topology is future cache/storage design work.
        services.AddSingleton<StorageContext>();

        // Repos | Connection pooling is in use. Singleton is the only option because of pooling.
        services.AddSingleton<IAccountRecoveryRepo, AccountRecoveryRepo>();
        services.AddSingleton<IAccountRepo, AccountRepo>();
        services.AddSingleton<IActivationRepo, ActivationRepo>();
        services.AddSingleton<ISessionRepo, SessionRepo>();
        services.AddSingleton<IPasswordResetRepo, PasswordResetRepo>();
        services.AddSingleton<IPasswordResetTotpRepo, PasswordResetTotpRepo>();
        services.AddSingleton<ISensitiveActionTokenRepo, SensitiveActionTokenRepo>();
        services.AddSingleton<IAuthenticatorAppEnrollmentRepo, AuthenticatorAppEnrollmentRepo>();

        services.AddSingleton<ITwoFactorSessionService, TwoFactorSessionService>();
        services.AddSingleton<IPasswordResetSessionService, PasswordResetSessionService>();
        services.AddSingleton<IActiveUserCacheService, ActiveUserCacheService>();
        services.AddSingleton<IAbuseCounterStore, DragonflyAbuseCounterStore>();
        services.AddSingleton<IDeliveryAbuseThrottleService, DeliveryAbuseThrottleService>();
        services.AddSingleton<IJsonWebTokenUtility, JsonWebTokenUtility>();
        services.AddSingleton<IUserSecretHasher, Argon2idUserSecretHasher>();
        services.AddSingleton<IPasswordResetCodeGenerator, PasswordResetCodeGenerator>();
        services.AddSingleton<ILoginAbuseCounterKeyFactory, LoginAbuseCounterKeyFactory>();
        services.AddSingleton<IPasswordResetCodeHasher, PasswordResetCodeHasher>();
        services.AddSingleton<IPasswordResetRateLimitKeyFactory, PasswordResetRateLimitKeyFactory>();
        services.AddSingleton<IPasswordResetAbuseCounterKeyFactory, PasswordResetAbuseCounterKeyFactory>();
        services.AddSingleton<IAccountUnlockAbuseCounterKeyFactory, AccountUnlockAbuseCounterKeyFactory>();
        services.AddSingleton<IAccountTokenVerificationAbuseCounterKeyFactory, AccountTokenVerificationAbuseCounterKeyFactory>();
        services.AddSingleton<IActivationAbuseCounterKeyFactory, ActivationAbuseCounterKeyFactory>();
        services.AddSingleton<IAuthenticatedMutationIdempotencyService, DragonflyAuthenticatedMutationIdempotencyService>();
        services.AddSingleton<IHealthDependencyService, HealthDependencyService>();
        services.AddSingleton<IPasswordResetAbusePolicy, PasswordResetAbusePolicy>();
        services.AddSingleton<IPasswordResetDeliveryService, PasswordResetDeliveryService>();
        services.AddSingleton<IPasswordResetTotpVerifier, PasswordResetTotpVerifier>();
        services.AddSingleton<IPasswordResetPasswordMaterialFactory, PasswordResetPasswordMaterialFactory>();
        services.AddSingleton<ITotpSecretProtector, TotpSecretProtector>();
        services.AddSingleton<ITotpCodeVerifier, TotpCodeVerifier>();
        services.AddSingleton<IAuthenticatorAppSecretGenerator, AuthenticatorAppSecretGenerator>();
        services.AddSingleton<IAuthenticatorAppBase32Encoder, AuthenticatorAppBase32Encoder>();
        services.AddSingleton<IAuthenticatorAppProvisioningUriBuilder, AuthenticatorAppProvisioningUriBuilder>();
        services.AddSingleton<ITotpProvider, LocalTotpProvider>();
        services.AddSingleton<ITotpProviderRegistry, TotpProviderRegistry>();

        // Services | Anything that doesn't speak to a Cache or Database is a candidate for Transient.
        services.AddSingleton<IAccountRecoveryService, AccountRecoveryService>();
        services.AddSingleton<IAccountService, AccountService>();
        services.AddSingleton<ITwoFactorAuthenticateService, TwoFactorAuthenticateService>();
        services.AddSingleton<IActivationService, ActivationService>();
        services.AddSingleton<IPasswordResetService, PasswordResetService>();
        services.AddSingleton<IAccountSensitiveActionService, AccountSensitiveActionService>();
        services.AddSingleton<IAuthenticatorAppSetupService, AuthenticatorAppSetupService>();
        services.AddSingleton<IAuthenticatorAppLoginVerifier, AuthenticatorAppLoginVerifier>();
        services.AddSingleton<HTTPService>();
        services.AddSingleton<ISystemTestDeliveryCapture, SystemTestDeliveryCapture>();
        SystemTestSettings systemTestSettings = configuration.GetSection("SystemTestSettings").Get<SystemTestSettings>() ?? new SystemTestSettings();
        if (systemTestSettings.Enabled)
        {
            services.AddSingleton<ISMTPService, SystemTestSmtpService>();
            services.AddSingleton<ISmsSender, SystemTestSmsSender>();
        }
        else
        {
            services.AddSingleton<ISMTPService, SMTPService>();
            services.AddSingleton<ISmsSender, SmsSender>();
        }

        services.AddSingleton<IAwsSnsSmsClient, AwsSnsSmsClient>();
        services.AddSingleton<IAWSService, AWSService>();
        services.AddSingleton<ITwilioMessageClient, TwilioMessageClient>();
        services.AddSingleton<ITwilioSmsService, TwilioSmsService>();
        services.AddSingleton<AspenTrees>();

        return services;
    }

    private static OptionsBuilder<TOptions> AddValidatedOptions<TOptions>(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName)
        where TOptions : class, new()
    {
        IConfigurationSection section = configuration.GetSection(sectionName);

        return services
            .AddOptions<TOptions>()
            .Bind(section)
            .Validate(_ => section.Exists(), $"{sectionName} configuration section is required.")
            .Validate(options => ConfigurationValidation.TryValidate(options, out _), $"{sectionName} configuration is invalid or incomplete.")
            .ValidateOnStart();
    }
}
