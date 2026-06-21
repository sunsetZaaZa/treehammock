using treehammock.Tests.System.Support;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Shouldly;

namespace treehammock.Tests.System;

public sealed class SystemStackAccountFlowTests
{
    private const string TestKeyHeaderName = "X-System-Test-Key";
    private const string IdempotencyKeyHeaderName = "Idempotency-Key";
    private const string SensitiveActionTokenHeaderName = "Sensitive-Action-Token";
    private const string Password = "CorrectHorseBatteryStaple1!";
    private static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(90);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task Registration_verify_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        string email = UniqueEmail();
        await RegisterAndVerify(client, email, Password, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Login_without_2fa_issues_active_session_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        user.AccessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Invalid_login_fails_without_leaking_account_state_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUser(client, TestContext.Current.CancellationToken);

        using JsonDocument login = await PostJson(client, "/account/requestaccess", new
        {
            emailAddress = user.Email,
            password = "WrongHorseBatteryStaple1!"
        }, HttpStatusCode.Unauthorized, TestContext.Current.CancellationToken);

        login.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
        login.RootElement.GetProperty("code").GetString().ShouldBe("AUTHENTICATION_FAILED");
        login.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe("AUTHENTICATION_FAILED");
    }

    [Fact]
    public async Task Setup_email_2fa_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupEmailTwoFactor(client, user, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Setup_sms_2fa_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Setup_authenticator_app_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        enrollment.ManualEntryKey.ShouldNotBeNullOrWhiteSpace();
        user.AccessToken = enrollment.RotatedAccessToken;
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;
    }

    [Fact]
    public async Task Setup_all_2fa_methods_then_login_advertises_all_verified_methods_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupEmailTwoFactor(client, user, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        user.AccessToken = enrollment.RotatedAccessToken;
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;

        using JsonDocument login = await LoginExpectingTwoFactor(client, user.Email, user.Password, TestContext.Current.CancellationToken);
        JsonElement methods = login.RootElement.GetProperty("data").GetProperty("twoFactorAuthMethods");
        ReadIntSet(methods).SetEquals(new[] { 1, 2, 3 }).ShouldBeTrue();
    }

    [Fact]
    public async Task Login_with_email_2fa_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupEmailTwoFactor(client, user, TestContext.Current.CancellationToken);

        string accessToken = await LoginWithEmailTwoFactor(client, user.Email, user.Password, TestContext.Current.CancellationToken);
        accessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Login_with_sms_2fa_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);

        string accessToken = await LoginWithSmsTwoFactor(client, user.Email, user.Password, user.SmsDestination, TestContext.Current.CancellationToken);
        accessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Login_with_authenticator_app_totp_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;

        string accessToken = await LoginWithAuthenticatorAppTwoFactor(client, user.Email, user.Password, user.AuthenticatorManualEntryKey, TestContext.Current.CancellationToken);
        accessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Login_with_sms_and_authenticator_app_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        user.AccessToken = enrollment.RotatedAccessToken;
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;

        string accessToken = await LoginWithSmsAndAuthenticatorAppTwoFactor(client, user.Email, user.Password, user.SmsDestination, user.AuthenticatorManualEntryKey, TestContext.Current.CancellationToken);
        accessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Wrong_login_2fa_code_fails_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupEmailTwoFactor(client, user, TestContext.Current.CancellationToken);

        using JsonDocument pending = await LoginExpectingTwoFactor(client, user.Email, user.Password, TestContext.Current.CancellationToken);
        string preAuthToken = pending.RootElement.GetProperty("data").GetProperty("twoFactorAccessToken").GetString() ?? string.Empty;
        await SelectTwoFactorMethod(client, preAuthToken, 1, null, "TWOFACTOR_WAITING_INTRA_EMAIL", TestContext.Current.CancellationToken);

        using JsonDocument final = await PostJson(client, "/account/twofactorauth", new
        {
            method = 1,
            codeKey = "000000"
        }, HttpStatusCode.Unauthorized, TestContext.Current.CancellationToken, request => request.Headers.Add("AccessToken", preAuthToken));

        final.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
    }



    [Fact]
    public async Task Password_reset_email_delivery_channel_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        string newPassword = "NewCorrectHorseBatteryStaple1!";

        await CompletePasswordReset(
            client,
            user.Email,
            "email",
            user.Email,
            newPassword,
            null,
            TestContext.Current.CancellationToken);

        using JsonDocument oldLogin = await PostJson(client, "/account/requestaccess", new
        {
            emailAddress = user.Email,
            password = user.Password
        }, HttpStatusCode.Unauthorized, TestContext.Current.CancellationToken);
        oldLogin.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();

        string newAccessToken = await LoginAndReturnAccessToken(client, user.Email, newPassword, TestContext.Current.CancellationToken);
        newAccessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Password_reset_sms_delivery_channel_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);

        await CompletePasswordReset(
            client,
            user.Email,
            "sms",
            user.SmsDestination,
            "NewCorrectHorseBatteryStaple2!",
            null,
            TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Password_reset_email_delivery_channel_plus_authenticator_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        user.AccessToken = enrollment.RotatedAccessToken;
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;

        await CompletePasswordReset(
            client,
            user.Email,
            "email",
            user.Email,
            "NewCorrectHorseBatteryStaple3!",
            user.AuthenticatorManualEntryKey,
            TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Password_reset_email_delivery_channel_plus_sms_and_authenticator_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        user.AccessToken = enrollment.RotatedAccessToken;
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;

        await CompletePasswordReset(
            client,
            user.Email,
            "email",
            user.Email,
            "NewCorrectHorseBatteryStaple5!",
            user.AuthenticatorManualEntryKey,
            TestContext.Current.CancellationToken,
            preferredTwoFactorConfiguration: 4,
            twoFactorSmsDestination: user.SmsDestination);
    }

    [Fact]
    public async Task Password_reset_sms_delivery_channel_plus_authenticator_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        user.AccessToken = enrollment.RotatedAccessToken;
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;

        await CompletePasswordReset(
            client,
            user.Email,
            "sms",
            user.SmsDestination,
            "NewCorrectHorseBatteryStaple4!",
            user.AuthenticatorManualEntryKey,
            TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task Account_delete_flow_finalizes_and_blocks_future_login_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);

        using JsonDocument requestDelete = await PostJson(
            client,
            "/account/wipeout",
            new { },
            HttpStatusCode.Accepted,
            TestContext.Current.CancellationToken,
            request => AddAuthenticatedMutationHeaders(request, user.AccessToken));
        requestDelete.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();

        string deleteToken = await LatestDeliveryCode(client, "email", "account_delete", user.Email, TestContext.Current.CancellationToken);
        deleteToken.ShouldNotBeNullOrWhiteSpace();

        using HttpResponseMessage verifyResponse = await client.GetAsync($"/account/wipeout/verify?payload={Uri.EscapeDataString(deleteToken)}", TestContext.Current.CancellationToken);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.OK);

        using JsonDocument finalize = await PostJson(
            client,
            "/account/wipeout/finalize",
            new { deleteToken },
            HttpStatusCode.OK,
            TestContext.Current.CancellationToken,
            request => AddAuthenticatedMutationHeaders(request, user.AccessToken));
        finalize.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();

        using JsonDocument login = await PostJson(client, "/account/requestaccess", new
        {
            emailAddress = user.Email,
            password = user.Password
        }, HttpStatusCode.Unauthorized, TestContext.Current.CancellationToken);
        login.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();

        using JsonDocument view = await AuthenticatedGetJson(client, "/account/view", user.AccessToken, HttpStatusCode.Unauthorized, TestContext.Current.CancellationToken);
        view.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Account_unlock_after_failed_password_lockout_succeeds_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        string email = UniqueEmail();
        await RegisterAndVerify(client, email, Password, TestContext.Current.CancellationToken);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            HttpStatusCode expected = attempt == 2 ? HttpStatusCode.Locked : HttpStatusCode.Unauthorized;
            using JsonDocument failed = await PostJson(client, "/account/requestaccess", new
            {
                emailAddress = email,
                password = $"WrongHorseBatteryStaple{attempt}!"
            }, expected, TestContext.Current.CancellationToken);
            failed.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
        }

        using JsonDocument start = await PostJson(client, "/account/unlock/start", new
        {
            identifier = email,
            deliveryMethod = "EMAIL"
        }, HttpStatusCode.Accepted, TestContext.Current.CancellationToken);
        start.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();

        string unlockToken = await LatestDeliveryCode(client, "email", "account_unlock", email, TestContext.Current.CancellationToken);
        unlockToken.ShouldNotBeNullOrWhiteSpace();

        using JsonDocument verify = await PostJson(client, "/account/unlock/verify", new
        {
            token = unlockToken
        }, HttpStatusCode.OK, TestContext.Current.CancellationToken);
        verify.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();

        string accessToken = await LoginAndReturnAccessToken(client, email, Password, TestContext.Current.CancellationToken);
        accessToken.ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task Removing_authenticator_keeps_sms_login_and_reset_options_exclude_authenticator_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);
        await ClearDeliveries(client, TestContext.Current.CancellationToken);

        SystemUser user = await SeedVerifiedUserAndLogin(client, TestContext.Current.CancellationToken);
        await SetupSmsTwoFactor(client, user, TestContext.Current.CancellationToken);
        AuthenticatorEnrollment enrollment = await SetupAuthenticatorApp(client, user, TestContext.Current.CancellationToken);
        user.AccessToken = enrollment.RotatedAccessToken;
        user.AuthenticatorManualEntryKey = enrollment.ManualEntryKey;

        using JsonDocument removed = await RemoveTwoFactorMethod(client, user, 3, TestContext.Current.CancellationToken);
        removed.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        JsonElement removalData = removed.RootElement.GetProperty("data");
        removalData.GetProperty("removedMethod").GetString().ShouldBe("AUTHENTICATOR_APP");
        ReadTwoFactorConfigurationSet(removalData.GetProperty("availableTwoFactorAuthConfigurations")).SetEquals(new[] { 1 }).ShouldBeTrue();

        string smsAccessToken = await LoginWithSmsTwoFactor(client, user.Email, user.Password, user.SmsDestination, TestContext.Current.CancellationToken);
        smsAccessToken.ShouldNotBeNullOrWhiteSpace();

        PasswordResetVerification verifiedReset = await StartAndVerifyPasswordReset(
            client,
            user.Email,
            "email",
            user.Email,
            TestContext.Current.CancellationToken);

        verifiedReset.Data.GetProperty("requiresTwoFactor").GetBoolean().ShouldBeTrue();
        HashSet<int> resetConfigurations = ReadTwoFactorConfigurationSet(verifiedReset.Data.GetProperty("availableTwoFactorAuthConfigurations"));
        resetConfigurations.SetEquals(new[] { 1 }).ShouldBeTrue();
        resetConfigurations.ShouldNotContain(3);
        resetConfigurations.ShouldNotContain(4);
        resetConfigurations.ShouldNotContain(5);
    }

    [Fact]
    public async Task Legacy_login_twofactor_method_endpoint_is_absent_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);

        using JsonContent content = JsonContent.Create(new
        {
            method = 1,
            destination = (short?)null
        }, options: JsonOptions);
        using HttpResponseMessage response = await client.PostAsync("/account/twofactormethod", content, TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Password_reset_authenticator_delivery_channel_is_rejected_through_haproxy()
    {
        using HttpClient client = CreateClient();
        await WaitUntilReadyAsync(client, TestContext.Current.CancellationToken);

        using JsonDocument rejected = await PostJson(client, "/account/password-reset/request", new
        {
            identifier = UniqueEmail(),
            deliveryChannel = "authenticator"
        }, HttpStatusCode.BadRequest, TestContext.Current.CancellationToken);

        rejected.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
        rejected.RootElement.GetProperty("code").GetString().ShouldBe("VALIDATION_FAILED");
        rejected.RootElement.GetProperty("errors").EnumerateArray()
            .Any(error => string.Equals(error.GetProperty("field").GetString(), "deliveryChannel", StringComparison.Ordinal))
            .ShouldBeTrue();
    }

    private static async Task<SystemUser> SeedVerifiedUserAndLogin(HttpClient client, CancellationToken cancellationToken)
    {
        SystemUser user = await SeedVerifiedUser(client, cancellationToken);
        user.AccessToken = await LoginAndReturnAccessToken(client, user.Email, user.Password, cancellationToken);
        return user;
    }

    private static async Task<SystemUser> SeedVerifiedUser(HttpClient client, CancellationToken cancellationToken)
    {
        string email = UniqueEmail();
        using JsonDocument seed = await PostJson(
            client,
            "/__system-test/accounts/verified",
            new
            {
                emailAddress = email,
                password = Password,
                country = "USA"
            },
            HttpStatusCode.OK,
            cancellationToken,
            request => request.Headers.Add(TestKeyHeaderName, SystemTestKey()));

        seed.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        seed.RootElement.GetProperty("code").GetString().ShouldBe("SYSTEM_TEST_ACCOUNT_SEEDED");
        return new SystemUser(email, Password, string.Empty);
    }

    private static async Task RegisterAndVerify(HttpClient client, string email, string password, CancellationToken cancellationToken)
    {
        using JsonDocument setup = await PostJson(client, "/account/setupaccount", new
        {
            emailAddress = email,
            password,
            country = "USA"
        }, HttpStatusCode.OK, cancellationToken);
        setup.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();

        string token = await LatestDeliveryCode(client, "email", "account_verify", email, cancellationToken);
        using HttpResponseMessage verifyResponse = await client.GetAsync($"/account/verifyaccount?payload={Uri.EscapeDataString(token)}", cancellationToken);
        verifyResponse.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    private static async Task SetupEmailTwoFactor(HttpClient client, SystemUser user, CancellationToken cancellationToken)
    {
        await SetupCodeTwoFactor(client, user.AccessToken, new
        {
            method = 1,
            contact = user.Email,
            countryCode = (short?)null,
            required = true
        }, cancellationToken);

        string code = await LatestDeliveryCode(client, "email", "two_factor_setup", user.Email, cancellationToken);
        await VerifySetupTwoFactor(client, user.AccessToken, 1, code, cancellationToken);
    }

    private static async Task SetupSmsTwoFactor(HttpClient client, SystemUser user, CancellationToken cancellationToken)
    {
        await SetupCodeTwoFactor(client, user.AccessToken, new
        {
            method = 2,
            contact = user.SmsPhone,
            countryCode = (short)1,
            required = true
        }, cancellationToken);

        string code = await LatestDeliveryCode(client, "sms", "two_factor_setup", user.SmsDestination, cancellationToken);
        await VerifySetupTwoFactor(client, user.AccessToken, 2, code, cancellationToken);
    }

    private static async Task SetupCodeTwoFactor(HttpClient client, string accessToken, object payload, CancellationToken cancellationToken)
    {
        using JsonDocument setup = await PostJson(
            client,
            "/account/setuptwofactormethod",
            payload,
            HttpStatusCode.Accepted,
            cancellationToken,
            request => AddAuthenticatedMutationHeaders(request, accessToken));

        setup.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
    }

    private static async Task VerifySetupTwoFactor(HttpClient client, string accessToken, int method, string code, CancellationToken cancellationToken)
    {
        using JsonDocument verify = await PostJson(
            client,
            "/account/verifytwofactormethod",
            new
            {
                method,
                codeKey = code
            },
            HttpStatusCode.OK,
            cancellationToken,
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken));

        verify.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        verify.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe("SUCCESS");
    }

    private static async Task<AuthenticatorEnrollment> SetupAuthenticatorApp(HttpClient client, SystemUser user, CancellationToken cancellationToken)
    {
        string sensitiveActionToken = await IssueSensitiveActionToken(client, user.AccessToken, user.Password, cancellationToken);
        using JsonDocument setup = await PostJson(
            client,
            "/account/twofactor/authenticator/setup",
            new
            {
                label = "system-flow",
                required = true,
                provider = 1
            },
            HttpStatusCode.Accepted,
            cancellationToken,
            request =>
            {
                AddAuthenticatedMutationHeaders(request, user.AccessToken);
                request.Headers.Add(SensitiveActionTokenHeaderName, sensitiveActionToken);
            });

        JsonElement data = setup.RootElement.GetProperty("data");
        string setupId = data.GetProperty("setupId").GetString() ?? string.Empty;
        string manualEntryKey = data.GetProperty("manualEntryKey").GetString() ?? string.Empty;
        int digits = data.TryGetProperty("digits", out JsonElement digitsElement) && digitsElement.ValueKind == JsonValueKind.Number
            ? digitsElement.GetInt32()
            : 6;
        int periodSeconds = data.TryGetProperty("periodSeconds", out JsonElement periodElement) && periodElement.ValueKind == JsonValueKind.Number
            ? periodElement.GetInt32()
            : 30;
        string hashAlgorithm = data.TryGetProperty("hashAlgorithm", out JsonElement hashElement) && hashElement.ValueKind == JsonValueKind.String
            ? hashElement.GetString() ?? "SHA1"
            : "SHA1";

        // Use the previous accepted TOTP step for enrollment so immediate follow-up login/reset
        // system tests can use the current step without tripping replay protection.
        string totpCode = TotpTestCodeGenerator.Generate(manualEntryKey, digits, periodSeconds, hashAlgorithm, DateTimeOffset.UtcNow.AddSeconds(-periodSeconds));
        using JsonDocument verify = await PostJson(
            client,
            "/account/twofactor/authenticator/verify",
            new
            {
                setupId,
                totpCode
            },
            HttpStatusCode.OK,
            cancellationToken,
            request =>
            {
                AddAuthenticatedMutationHeaders(request, user.AccessToken);
                request.Headers.Add(SensitiveActionTokenHeaderName, sensitiveActionToken);
            });

        verify.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        string rotatedAccessToken = verify.RootElement.GetProperty("data").GetProperty("accessToken").GetString() ?? string.Empty;
        return new AuthenticatorEnrollment(manualEntryKey, rotatedAccessToken);
    }

    private static async Task<string> IssueSensitiveActionToken(HttpClient client, string accessToken, string password, CancellationToken cancellationToken, int purpose = 1)
    {
        using JsonDocument reauthenticate = await PostJson(
            client,
            "/account/reauthenticate",
            new
            {
                password,
                purpose
            },
            HttpStatusCode.OK,
            cancellationToken,
            request => request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken));

        return reauthenticate.RootElement.GetProperty("data").GetProperty("sensitiveActionToken").GetString() ?? string.Empty;
    }

    private static async Task<string> LoginAndReturnAccessToken(HttpClient client, string email, string password, CancellationToken cancellationToken)
    {
        using JsonDocument login = await PostJson(client, "/account/requestaccess", new
        {
            emailAddress = email,
            password
        }, HttpStatusCode.OK, cancellationToken);

        login.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        login.RootElement.GetProperty("code").GetString().ShouldBe("AUTHENTICATION_PASSED");
        return login.RootElement.GetProperty("data").GetProperty("accessToken").GetString() ?? string.Empty;
    }

    private static async Task<JsonDocument> LoginExpectingTwoFactor(HttpClient client, string email, string password, CancellationToken cancellationToken)
    {
        using JsonDocument login = await PostJson(client, "/account/requestaccess", new
        {
            emailAddress = email,
            password
        }, HttpStatusCode.OK, cancellationToken);

        login.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        login.RootElement.GetProperty("code").GetString().ShouldBe("AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED");
        return JsonDocument.Parse(login.RootElement.GetRawText());
    }

    private static async Task<string> LoginWithEmailTwoFactor(HttpClient client, string email, string password, CancellationToken cancellationToken)
    {
        using JsonDocument pending = await LoginExpectingTwoFactor(client, email, password, cancellationToken);
        string preAuthToken = pending.RootElement.GetProperty("data").GetProperty("twoFactorAccessToken").GetString() ?? string.Empty;
        await SelectTwoFactorMethod(client, preAuthToken, 1, null, "TWOFACTOR_WAITING_INTRA_EMAIL", cancellationToken);
        string code = await LatestDeliveryCode(client, "email", "two_factor_login", email, cancellationToken);
        return await CompleteTwoFactorLogin(client, preAuthToken, 1, code, cancellationToken);
    }

    private static async Task<string> LoginWithSmsTwoFactor(HttpClient client, string email, string password, string smsDestination, CancellationToken cancellationToken)
    {
        using JsonDocument pending = await LoginExpectingTwoFactor(client, email, password, cancellationToken);
        string preAuthToken = pending.RootElement.GetProperty("data").GetProperty("twoFactorAccessToken").GetString() ?? string.Empty;
        await SelectTwoFactorMethod(client, preAuthToken, 2, 0, "TWOFACTOR_WAITING_SMS_KEY", cancellationToken);
        string code = await LatestDeliveryCode(client, "sms", "two_factor_login", smsDestination, cancellationToken);
        return await CompleteTwoFactorLogin(client, preAuthToken, 2, code, cancellationToken);
    }

    private static async Task<string> LoginWithAuthenticatorAppTwoFactor(HttpClient client, string email, string password, string manualEntryKey, CancellationToken cancellationToken)
    {
        using JsonDocument pending = await LoginExpectingTwoFactor(client, email, password, cancellationToken);
        string preAuthToken = pending.RootElement.GetProperty("data").GetProperty("twoFactorAccessToken").GetString() ?? string.Empty;
        await SelectTwoFactorMethod(client, preAuthToken, 3, null, "TWOFACTOR_WAITING_AUTHENTICATOR_APP", cancellationToken);
        string code = TotpTestCodeGenerator.Generate(manualEntryKey, 6, 30, "SHA1", DateTimeOffset.UtcNow);
        return await CompleteTwoFactorLogin(client, preAuthToken, 3, code, cancellationToken);
    }

    private static async Task<string> LoginWithSmsAndAuthenticatorAppTwoFactor(HttpClient client, string email, string password, string smsDestination, string manualEntryKey, CancellationToken cancellationToken)
    {
        using JsonDocument pending = await LoginExpectingTwoFactor(client, email, password, cancellationToken);
        string preAuthToken = pending.RootElement.GetProperty("data").GetProperty("twoFactorAccessToken").GetString() ?? string.Empty;
        await SelectTwoFactorConfiguration(client, preAuthToken, "SMS_AND_AUTHENTICATOR_APP", 0, "TWOFACTOR_WAITING_SMS_KEY", cancellationToken);

        string smsCode = await LatestDeliveryCode(client, "sms", "two_factor_login", smsDestination, cancellationToken);
        using JsonDocument smsProof = await PostJson(
            client,
            "/account/twofactorauth",
            new
            {
                method = 2,
                codeKey = smsCode
            },
            HttpStatusCode.OK,
            cancellationToken,
            request => request.Headers.Add("AccessToken", preAuthToken));

        smsProof.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        smsProof.RootElement.GetProperty("code").GetString().ShouldBe("AUTHENTICATION_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED");
        smsProof.RootElement.GetProperty("data").GetProperty("currentRequiredMethod").GetString().ShouldBe("AUTHENTICATOR_APP");

        string authenticatorCode = TotpTestCodeGenerator.Generate(manualEntryKey, 6, 30, "SHA1", DateTimeOffset.UtcNow);
        return await CompleteTwoFactorLogin(client, preAuthToken, 3, authenticatorCode, cancellationToken);
    }

    private static async Task SelectTwoFactorMethod(HttpClient client, string preAuthToken, int method, short? destination, string expectedResult, CancellationToken cancellationToken)
    {
        string configuration = method switch
        {
            1 => "EMAIL",
            2 => "SMS",
            3 => "AUTHENTICATOR_APP",
            _ => throw new ArgumentOutOfRangeException(nameof(method), method, "Unsupported test 2FA method.")
        };

        await SelectTwoFactorConfiguration(client, preAuthToken, configuration, destination, expectedResult, cancellationToken);
    }

    private static async Task SelectTwoFactorConfiguration(HttpClient client, string preAuthToken, string configuration, short? destination, string expectedResult, CancellationToken cancellationToken)
    {
        object body = destination.HasValue
            ? new { configuration, destination = destination.Value, twoFactorAccessToken = preAuthToken }
            : new { configuration, twoFactorAccessToken = preAuthToken };

        using JsonDocument challenge = await PostJson(
            client,
            "/account/twofactor/select",
            body,
            HttpStatusCode.OK,
            cancellationToken);

        challenge.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        challenge.RootElement.GetProperty("code").GetString().ShouldBe(expectedResult);
    }

    private static async Task<string> CompleteTwoFactorLogin(HttpClient client, string preAuthToken, int method, string code, CancellationToken cancellationToken)
    {
        using JsonDocument final = await PostJson(
            client,
            "/account/twofactorauth",
            new
            {
                method,
                codeKey = code
            },
            HttpStatusCode.OK,
            cancellationToken,
            request => request.Headers.Add("AccessToken", preAuthToken));

        final.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        final.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe("SUCCESS");
        return final.RootElement.GetProperty("data").GetProperty("accessToken").GetString() ?? string.Empty;
    }



    private static async Task<JsonDocument> RemoveTwoFactorMethod(HttpClient client, SystemUser user, int method, CancellationToken cancellationToken)
    {
        string sensitiveActionToken = await IssueSensitiveActionToken(client, user.AccessToken, user.Password, cancellationToken, purpose: 2);
        using JsonDocument removed = await PostJson(
            client,
            "/account/twofactor/method/remove",
            new { method },
            HttpStatusCode.OK,
            cancellationToken,
            request =>
            {
                AddAuthenticatedMutationHeaders(request, user.AccessToken);
                request.Headers.Add(SensitiveActionTokenHeaderName, sensitiveActionToken);
            });

        return JsonDocument.Parse(removed.RootElement.GetRawText());
    }

    private static async Task<PasswordResetVerification> StartAndVerifyPasswordReset(
        HttpClient client,
        string identifier,
        string deliveryChannel,
        string deliveryDestination,
        CancellationToken cancellationToken)
    {
        using JsonDocument request = await PostJson(client, "/account/password-reset/request", new
        {
            identifier,
            deliveryChannel
        }, HttpStatusCode.Accepted, cancellationToken);
        request.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        Guid resetId = request.RootElement.GetProperty("data").GetProperty("resetId").GetGuid();
        resetId.ShouldNotBe(Guid.Empty);

        string keyCode = await LatestDeliveryCode(client, deliveryChannel, "password_reset", deliveryDestination, cancellationToken);
        keyCode.ShouldNotBeNullOrWhiteSpace();

        using JsonDocument verified = await PostJson(client, "/account/password-reset/verify", new
        {
            resetId,
            keyCode
        }, HttpStatusCode.OK, cancellationToken);
        verified.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();

        JsonElement data = verified.RootElement.GetProperty("data").Clone();
        string resetAccessToken = data.GetProperty("resetAccessToken").GetString() ?? string.Empty;
        resetAccessToken.ShouldNotBeNullOrWhiteSpace();
        return new PasswordResetVerification(resetAccessToken, data);
    }


    private static async Task CompletePasswordReset(
        HttpClient client,
        string identifier,
        string deliveryChannel,
        string deliveryDestination,
        string newPassword,
        string? authenticatorManualEntryKey,
        CancellationToken cancellationToken,
        int? preferredTwoFactorConfiguration = null,
        string? twoFactorSmsDestination = null)
    {
        using JsonDocument request = await PostJson(client, "/account/password-reset/request", new
        {
            identifier,
            deliveryChannel
        }, HttpStatusCode.Accepted, cancellationToken);
        request.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        Guid resetId = request.RootElement.GetProperty("data").GetProperty("resetId").GetGuid();
        resetId.ShouldNotBe(Guid.Empty);

        string keyCode = await LatestDeliveryCode(client, deliveryChannel, "password_reset", deliveryDestination, cancellationToken);
        keyCode.ShouldNotBeNullOrWhiteSpace();

        using JsonDocument verified = await PostJson(client, "/account/password-reset/verify", new
        {
            resetId,
            keyCode
        }, HttpStatusCode.OK, cancellationToken);

        verified.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        string resetAccessToken = verified.RootElement.GetProperty("data").GetProperty("resetAccessToken").GetString() ?? string.Empty;
        resetAccessToken.ShouldNotBeNullOrWhiteSpace();

        bool requiresTwoFactor = verified.RootElement.GetProperty("data").GetProperty("requiresTwoFactor").GetBoolean();
        if (requiresTwoFactor)
        {
            JsonElement configurations = verified.RootElement.GetProperty("data").GetProperty("availableTwoFactorAuthConfigurations");
            HashSet<int> availableConfigurations = ReadTwoFactorConfigurationSet(configurations);
            int configuration = preferredTwoFactorConfiguration ?? ChoosePasswordResetTwoFactorConfiguration(configurations, authenticatorManualEntryKey);
            configuration.ShouldNotBe(0);
            availableConfigurations.ShouldContain(configuration);

            using JsonDocument selected = await PostJson(client, "/account/password-reset/twofactor/select", new
            {
                resetAccessToken,
                configuration
            }, HttpStatusCode.OK, cancellationToken);

            selected.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
            await CompletePasswordResetTwoFactorProofs(
                client,
                selected.RootElement.GetProperty("data"),
                resetAccessToken,
                identifier,
                twoFactorSmsDestination ?? deliveryDestination,
                authenticatorManualEntryKey,
                cancellationToken);
        }

        using JsonDocument finalize = await PostJson(client, "/account/password-reset/finalize", new
        {
            resetAccessToken,
            password = newPassword,
            verifyPassword = newPassword
        }, HttpStatusCode.OK, cancellationToken);

        finalize.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        finalize.RootElement.GetProperty("code").GetString().ShouldBe("PASSWORD_RESET_COMPLETED");
        finalize.RootElement.GetProperty("data").GetProperty("status").GetString().ShouldBe("completed");
    }


    private static int ChoosePasswordResetTwoFactorConfiguration(JsonElement configurations, string? authenticatorManualEntryKey)
    {
        HashSet<int> available = ReadTwoFactorConfigurationSet(configurations);
        if (!string.IsNullOrWhiteSpace(authenticatorManualEntryKey) && available.Contains(3))
        {
            return 3;
        }

        if (available.Contains(2))
        {
            return 2;
        }

        if (available.Contains(1))
        {
            return 1;
        }

        if (!string.IsNullOrWhiteSpace(authenticatorManualEntryKey) && available.Contains(4))
        {
            return 4;
        }

        if (!string.IsNullOrWhiteSpace(authenticatorManualEntryKey) && available.Contains(5))
        {
            return 5;
        }

        return 0;
    }

    private static async Task CompletePasswordResetTwoFactorProofs(
        HttpClient client,
        JsonElement selectedData,
        string resetAccessToken,
        string emailDestination,
        string smsDestination,
        string? authenticatorManualEntryKey,
        CancellationToken cancellationToken)
    {
        JsonElement data = selectedData.Clone();
        while (!data.GetProperty("canChangePassword").GetBoolean())
        {
            int currentRequiredMethod = ReadTwoFactorMethodValue(data.GetProperty("currentRequiredMethod"));
            string code = currentRequiredMethod switch
            {
                1 => await LatestDeliveryCode(client, "email", "password_reset", emailDestination, cancellationToken),
                2 => await LatestDeliveryCode(client, "sms", "password_reset", smsDestination, cancellationToken),
                3 when !string.IsNullOrWhiteSpace(authenticatorManualEntryKey) =>
                    TotpTestCodeGenerator.Generate(authenticatorManualEntryKey, 6, 30, "SHA1", DateTimeOffset.UtcNow),
                _ => string.Empty
            };

            code.ShouldNotBeNullOrWhiteSpace();
            using JsonDocument proof = await PostJson(client, "/account/password-reset/twofactor/verify", new
            {
                resetAccessToken,
                method = currentRequiredMethod,
                code
            }, HttpStatusCode.OK, cancellationToken);

            proof.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
            data = proof.RootElement.GetProperty("data").Clone();
        }
    }

    private static async Task<JsonDocument> PostJson(
        HttpClient client,
        string path,
        object body,
        HttpStatusCode expectedStatus,
        CancellationToken cancellationToken,
        Action<HttpRequestMessage>? configureRequest = null)
    {
        using JsonContent content = JsonContent.Create(body, options: JsonOptions);
        using HttpRequestMessage request = new(HttpMethod.Post, path)
        {
            Content = content
        };
        configureRequest?.Invoke(request);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        string responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
        response.StatusCode.ShouldBe(expectedStatus, responseContent);
        return JsonDocument.Parse(responseContent);
    }

    private static async Task<JsonDocument> AuthenticatedGetJson(HttpClient client, string path, string accessToken, HttpStatusCode expectedStatus, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        string content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.StatusCode.ShouldBe(expectedStatus, content);
        return JsonDocument.Parse(content);
    }

    private static void AddAuthenticatedMutationHeaders(HttpRequestMessage request, string accessToken)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Add(IdempotencyKeyHeaderName, $"system:{Guid.NewGuid():N}");
    }

    private static async Task<string> LatestDeliveryCode(HttpClient client, string channel, string purpose, string destination, CancellationToken cancellationToken)
    {
        string uri = $"/__system-test/deliveries/latest?channel={Uri.EscapeDataString(channel)}&purpose={Uri.EscapeDataString(purpose)}&destination={Uri.EscapeDataString(destination)}";
        using HttpRequestMessage request = new(HttpMethod.Get, uri);
        request.Headers.Add(TestKeyHeaderName, SystemTestKey());
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        string content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, content);
        using JsonDocument document = JsonDocument.Parse(content);
        JsonElement data = document.RootElement.GetProperty("data");
        if (data.TryGetProperty("code", out JsonElement code) || data.TryGetProperty("Code", out code))
        {
            return code.GetString() ?? string.Empty;
        }

        return string.Empty;
    }

    private static async Task ClearDeliveries(HttpClient client, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Delete, "/__system-test/deliveries");
        request.Headers.Add(TestKeyHeaderName, SystemTestKey());
        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
        (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.NotFound).ShouldBeTrue($"Unexpected delivery-clear status: {response.StatusCode}");
    }

    private static async Task WaitUntilReadyAsync(HttpClient client, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await RetryUntilSuccessAsync(client, "/health/ready", cancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    private static HttpClient CreateClient()
    {
        string baseUrl = TreehammockEnvironment.GetValue("TREEHAMMOCK_SYSTEM_BASE_URL", "http://haproxy:8080");
        return new HttpClient { BaseAddress = new Uri(baseUrl, UriKind.Absolute) };
    }

    private static string SystemTestKey()
    {
        return TreehammockEnvironment.GetValue("TREEHAMMOCK_SYSTEM_TEST_KEY", "treehammock-system-test-key");
    }

    private static string UniqueEmail()
    {
        return $"system-{Guid.NewGuid():N}@example.test";
    }

    private static string UniqueSmsPhone()
    {
        return $"555{RandomNumberGenerator.GetInt32(1_000_000, 10_000_000):D7}";
    }


    private static HashSet<int> ReadTwoFactorConfigurationSet(JsonElement array)
    {
        HashSet<int> values = new();
        foreach (JsonElement item in array.EnumerateArray())
        {
            values.Add(item.ValueKind == JsonValueKind.Number ? item.GetInt32() : item.GetString() switch
            {
                "SMS" => 1,
                "EMAIL" => 2,
                "AUTHENTICATOR_APP" => 3,
                "SMS_AND_AUTHENTICATOR_APP" => 4,
                "EMAIL_AND_AUTHENTICATOR_APP" => 5,
                _ => -1
            });
        }

        values.Remove(-1);
        return values;
    }

    private static int ReadTwoFactorMethodValue(JsonElement item)
    {
        return item.ValueKind == JsonValueKind.Number ? item.GetInt32() : item.GetString() switch
        {
            "EMAIL" => 1,
            "SMS_KEY" => 2,
            "AUTHENTICATOR_APP" => 3,
            _ => 0
        };
    }

    private static HashSet<int> ReadIntSet(JsonElement array)
    {
        HashSet<int> values = new();
        foreach (JsonElement item in array.EnumerateArray())
        {
            values.Add(item.ValueKind == JsonValueKind.Number ? item.GetInt32() : item.GetString() switch
            {
                "EMAIL" => 1,
                "SMS_KEY" => 2,
                "AUTHENTICATOR_APP" => 3,
                _ => -1
            });
        }

        values.Remove(-1);
        return values;
    }

    private static async Task<HttpResponseMessage> RetryUntilSuccessAsync(
        HttpClient client,
        string requestUri,
        CancellationToken cancellationToken)
    {
        DateTimeOffset deadline = DateTimeOffset.UtcNow.Add(ReadyTimeout);
        Exception? lastException = null;
        HttpStatusCode? lastStatusCode = null;

        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                HttpResponseMessage response = await client.GetAsync(requestUri, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    return response;
                }

                lastStatusCode = response.StatusCode;
                response.Dispose();
            }
            catch (HttpRequestException ex)
            {
                lastException = ex;
            }
            catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
            {
                lastException = ex;
            }

            await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
        }

        string reason = lastStatusCode is not null
            ? $"Last status code was {(int)lastStatusCode.Value} ({lastStatusCode.Value})."
            : $"Last exception was {lastException?.GetType().Name}: {lastException?.Message}";
        throw new TimeoutException($"Timed out waiting for {requestUri} to become healthy. {reason}", lastException);
    }

    private sealed class SystemUser
    {
        public SystemUser(string email, string password, string accessToken)
        {
            Email = email;
            Password = password;
            AccessToken = accessToken;
            SmsPhone = UniqueSmsPhone();
            SmsDestination = $"+1{SmsPhone}";
        }

        public string Email { get; }
        public string Password { get; }
        public string AccessToken { get; set; }
        public string SmsPhone { get; }
        public string SmsDestination { get; }
        public string AuthenticatorManualEntryKey { get; set; } = string.Empty;
    }

    private sealed record AuthenticatorEnrollment(string ManualEntryKey, string RotatedAccessToken);

    private sealed record PasswordResetVerification(string ResetAccessToken, JsonElement Data);
}

internal static class TotpTestCodeGenerator
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Generate(string manualEntryKey, int digits, int periodSeconds, string hashAlgorithm, DateTimeOffset timestamp)
    {
        byte[] secret = DecodeBase32(manualEntryKey);
        long timeStep = timestamp.ToUnixTimeSeconds() / periodSeconds;
        byte[] counter = BitConverter.GetBytes(timeStep);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(counter);
        }

        byte[] hmac = hashAlgorithm.ToUpperInvariant() switch
        {
            "SHA1" => HMACSHA1.HashData(secret, counter),
            "SHA256" => HMACSHA256.HashData(secret, counter),
            "SHA512" => HMACSHA512.HashData(secret, counter),
            _ => HMACSHA1.HashData(secret, counter)
        };

        int offset = hmac[^1] & 0x0f;
        int binaryCode = ((hmac[offset] & 0x7f) << 24)
            | ((hmac[offset + 1] & 0xff) << 16)
            | ((hmac[offset + 2] & 0xff) << 8)
            | (hmac[offset + 3] & 0xff);

        int modulus = 1;
        for (int i = 0; i < digits; i++)
        {
            modulus *= 10;
        }

        return (binaryCode % modulus).ToString($"D{digits}");
    }

    private static byte[] DecodeBase32(string value)
    {
        string normalized = value.Trim().TrimEnd('=').Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
        List<byte> bytes = new();
        int buffer = 0;
        int bitsLeft = 0;

        foreach (char current in normalized)
        {
            int index = Alphabet.IndexOf(current);
            if (index < 0)
            {
                continue;
            }

            buffer = (buffer << 5) | index;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 0xff));
                bitsLeft -= 8;
            }
        }

        return bytes.ToArray();
    }
}
