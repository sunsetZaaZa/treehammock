using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AccountServiceSetupTests
{
    [Fact]
    public async Task SetupUserAccount_successful_creation_starts_verification_and_sends_email()
    {
        var harness = CreateServiceHarness();
        Account? capturedAccount = null;
        string? capturedVerifyKeyHash = null;
        string? emailedVerificationUrl = null;
        harness.AccountRepo.SetupAccount(
                Arg.Do<Account>(account => capturedAccount = account),
                Arg.Do<string>(verifyKeyHash => capturedVerifyKeyHash = verifyKeyHash),
                Arg.Any<Period>(),
                AccountSetupAction.BOTH)
            .Returns(Task.FromResult<(long?, HttpMessage, string?)>((42, HttpMessage.ACCOUNT_CREATION_SUCCESSED, null)));
        harness.AccountRepo.StartAccountVerification(Arg.Any<Guid>(), 42).Returns(Task.FromResult<bool?>(true));
        harness.SmtpService.VerificationLetter("reader@example.com", harness.EmailSubjectSettings.AccountVerify, Arg.Do<string>(verificationUrl => emailedVerificationUrl = verificationUrl))
            .Returns(Task.FromResult<bool?>(true));

        HttpMessage result = await harness.Service.SetupUserAccount(
            "reader@example.com",
            "reader",
            "ValidPassword1!",
            Country.USA,
            SystemClock.Instance.GetCurrentInstant(),
            AccountSetupAction.BOTH);

        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_SUCCESSED);
        capturedAccount.ShouldNotBeNull();
        capturedAccount.hashedPassword.Length.ShouldBe(AccountCryptoSizes.PasswordHashBytes);
        capturedAccount.saltOne.Length.ShouldBe(AccountCryptoSizes.SaltOneBytes);
        capturedAccount.siv.Length.ShouldBe(AccountCryptoSizes.SivBytes);
        capturedAccount.nonce.Length.ShouldBe(AccountCryptoSizes.NonceBytes);
        capturedAccount.webKey.Length.ShouldBe(AccountCryptoSizes.WebKeyBase64UrlLength);
        capturedAccount.webKey.ShouldNotContain("\0");
        capturedAccount.webKey.ShouldNotContain("+");
        capturedAccount.webKey.ShouldNotContain("/");
        capturedAccount.unlockWhen.ShouldBeNull();
        capturedVerifyKeyHash.ShouldNotBeNullOrWhiteSpace();
        capturedVerifyKeyHash!.Length.ShouldBe(64);
        capturedVerifyKeyHash.ShouldBe(capturedVerifyKeyHash.ToLowerInvariant());
        emailedVerificationUrl.ShouldNotBeNullOrWhiteSpace();
        emailedVerificationUrl.ShouldStartWith("http://localhost.test/account/verifyaccount?payload=");
        emailedVerificationUrl.ShouldNotBe(capturedVerifyKeyHash);
        await harness.AccountRepo.Received(1).StartAccountVerification(capturedAccount.accountId, 42);
        await harness.SmtpService.Received(1).VerificationLetter("reader@example.com", harness.EmailSubjectSettings.AccountVerify, emailedVerificationUrl!);
    }

    [Theory]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL)]
    public async Task SetupUserAccount_returns_duplicate_result_without_sending_verification(HttpMessage duplicateResult)
    {
        var harness = CreateServiceHarness();
        harness.AccountRepo.SetupAccount(Arg.Any<Account>(), Arg.Any<string>(), Arg.Any<Period>(), AccountSetupAction.BOTH)
            .Returns(Task.FromResult<(long?, HttpMessage, string?)>((null, duplicateResult, null)));

        HttpMessage result = await harness.Service.SetupUserAccount(
            "reader@example.com",
            "reader",
            "ValidPassword1!",
            Country.USA,
            SystemClock.Instance.GetCurrentInstant(),
            AccountSetupAction.BOTH);

        result.ShouldBe(duplicateResult);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().StartAccountVerification(default, default);
        _ = harness.SmtpService.DidNotReceiveWithAnyArgs().VerificationLetter(default!, default!, default!);
    }

    [Fact]
    public async Task SetupUserAccount_failed_email_send_returns_pending_verification_so_resend_can_recover()
    {
        var harness = CreateServiceHarness();
        harness.AccountRepo.SetupAccount(Arg.Any<Account>(), Arg.Any<string>(), Arg.Any<Period>(), AccountSetupAction.EMAIL)
            .Returns(Task.FromResult<(long?, HttpMessage, string?)>((7, HttpMessage.ACCOUNT_CREATION_SUCCESSED, null)));
        harness.AccountRepo.StartAccountVerification(Arg.Any<Guid>(), 7).Returns(Task.FromResult<bool?>(true));
        harness.SmtpService.VerificationLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));

        HttpMessage result = await harness.Service.SetupUserAccount(
            "reader@example.com",
            null,
            "ValidPassword1!",
            Country.USA,
            SystemClock.Instance.GetCurrentInstant(),
            AccountSetupAction.EMAIL);

        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
    }

    [Fact]
    public async Task SetupUserAccount_failed_start_verification_returns_deterministic_verification_failure_without_sending_email()
    {
        var harness = CreateServiceHarness();
        harness.AccountRepo.SetupAccount(Arg.Any<Account>(), Arg.Any<string>(), Arg.Any<Period>(), AccountSetupAction.EMAIL)
            .Returns(Task.FromResult<(long?, HttpMessage, string?)>((7, HttpMessage.ACCOUNT_CREATION_SUCCESSED, null)));
        harness.AccountRepo.StartAccountVerification(Arg.Any<Guid>(), 7).Returns(Task.FromResult<bool?>(false));

        HttpMessage result = await harness.Service.SetupUserAccount(
            "reader@example.com",
            null,
            "ValidPassword1!",
            Country.USA,
            SystemClock.Instance.GetCurrentInstant(),
            AccountSetupAction.EMAIL);

        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_FAILED);
        _ = harness.SmtpService.DidNotReceiveWithAnyArgs().VerificationLetter(default!, default!, default!);
    }

    [Fact]
    public async Task ResendAccountVerification_sends_new_verification_url_when_repo_returns_target_email()
    {
        var harness = CreateServiceHarness();
        string? emailedVerificationUrl = null;
        harness.AccountRepo.ResendAccountVerification("reader@example.com", Arg.Any<string>(), Arg.Any<Period>())
            .Returns(Task.FromResult<AccountVerificationResendResult?>(new AccountVerificationResendResult(true, "VERIFICATION_RESEND_STARTED", "reader@example.com")));
        harness.SmtpService.ResendVerifyLetter("reader@example.com", harness.EmailSubjectSettings.AccountVerifyResend, Arg.Do<string>(url => emailedVerificationUrl = url))
            .Returns(Task.FromResult<bool?>(true));

        HttpMessage result = await harness.Service.ResendAccountVerification("reader@example.com");

        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_RESENT);
        emailedVerificationUrl.ShouldNotBeNullOrWhiteSpace();
        emailedVerificationUrl.ShouldStartWith("http://localhost.test/account/verifyaccount?payload=");
    }

    [Fact]
    public async Task ResendAccountVerification_email_failure_keeps_verification_pending()
    {
        var harness = CreateServiceHarness();
        harness.AccountRepo.ResendAccountVerification("reader@example.com", Arg.Any<string>(), Arg.Any<Period>())
            .Returns(Task.FromResult<AccountVerificationResendResult?>(new AccountVerificationResendResult(true, "VERIFICATION_RESEND_STARTED", "reader@example.com")));
        harness.SmtpService.ResendVerifyLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));

        HttpMessage result = await harness.Service.ResendAccountVerification("reader@example.com");

        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
    }

    [Fact]
    public async Task RequestEmailChange_hashes_raw_token_and_sends_verification_url_to_new_email()
    {
        var harness = CreateServiceHarness();
        string? capturedVerifyKeyHash = null;
        Instant? capturedExpiration = null;
        string? emailedVerificationUrl = null;
        harness.AccountRepo.RequestEmailChange(
                Arg.Any<Guid>(),
                Arg.Any<Guid>(),
                "new@example.com",
                Arg.Do<string>(hash => capturedVerifyKeyHash = hash),
                Arg.Do<Instant>(expiration => capturedExpiration = expiration))
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING", null, "new@example.com")));
        harness.SmtpService.EmailChangeVerifyLetter("new@example.com", harness.EmailSubjectSettings.AccountEmailChangeVerify, Arg.Do<string>(url => emailedVerificationUrl = url))
            .Returns(Task.FromResult<bool?>(true));

        AccountAdjustResult? result = await harness.Service.RequestEmailChange(Guid.NewGuid(), Guid.NewGuid(), "new@example.com");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING");
        result.EmailAddress.ShouldBe("new@example.com");
        capturedVerifyKeyHash.ShouldNotBeNullOrWhiteSpace();
        capturedVerifyKeyHash!.Length.ShouldBe(64);
        capturedExpiration.ShouldNotBeNull();
        emailedVerificationUrl.ShouldNotBeNullOrWhiteSpace();
        emailedVerificationUrl.ShouldStartWith("http://localhost.test/account/adjust/email/verify?payload=");
        emailedVerificationUrl.ShouldNotContain(capturedVerifyKeyHash);
    }

    [Fact]
    public async Task RequestEmailChange_email_failure_cancels_pending_request_and_returns_delivery_failed()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? capturedVerifyKeyHash = null;
        harness.AccountRepo.RequestEmailChange(
                accountId,
                accountSecurityStamp,
                "new@example.com",
                Arg.Do<string>(hash => capturedVerifyKeyHash = hash),
                Arg.Any<Instant>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING", null, "new@example.com")));
        harness.SmtpService.EmailChangeVerifyLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));
        harness.AccountRepo.CancelEmailChangeRequest(accountId, accountSecurityStamp, Arg.Any<string>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_CHANGE_CANCELLED", null, "new@example.com")));

        AccountAdjustResult? result = await harness.Service.RequestEmailChange(accountId, accountSecurityStamp, "new@example.com");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED");
        capturedVerifyKeyHash.ShouldNotBeNullOrWhiteSpace();
        await harness.AccountRepo.Received(1).CancelEmailChangeRequest(accountId, accountSecurityStamp, capturedVerifyKeyHash!);
    }

    [Fact]
    public async Task RequestEmailChange_email_exception_cancels_pending_request_and_returns_delivery_failed()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? capturedVerifyKeyHash = null;
        harness.AccountRepo.RequestEmailChange(
                accountId,
                accountSecurityStamp,
                "new@example.com",
                Arg.Do<string>(hash => capturedVerifyKeyHash = hash),
                Arg.Any<Instant>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING", null, "new@example.com")));
        harness.SmtpService.EmailChangeVerifyLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromException<bool?>(new InvalidOperationException("smtp failed")));
        harness.AccountRepo.CancelEmailChangeRequest(accountId, accountSecurityStamp, Arg.Any<string>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_CHANGE_CANCELLED", null, "new@example.com")));

        AccountAdjustResult? result = await harness.Service.RequestEmailChange(accountId, accountSecurityStamp, "new@example.com");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_ADJUST_EMAIL_DELIVERY_FAILED");
        capturedVerifyKeyHash.ShouldNotBeNullOrWhiteSpace();
        await harness.AccountRepo.Received(1).CancelEmailChangeRequest(accountId, accountSecurityStamp, capturedVerifyKeyHash!);
    }

    [Fact]
    public async Task RequestEmailChange_cleanup_failure_returns_cleanup_failed()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.AccountRepo.RequestEmailChange(accountId, accountSecurityStamp, "new@example.com", Arg.Any<string>(), Arg.Any<Instant>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_EMAIL_VERIFICATION_PENDING", null, "new@example.com")));
        harness.SmtpService.EmailChangeVerifyLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));
        harness.AccountRepo.CancelEmailChangeRequest(accountId, accountSecurityStamp, Arg.Any<string>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(false, "ACCOUNT_ADJUST_TOKEN_MISMATCH")));

        AccountAdjustResult? result = await harness.Service.RequestEmailChange(accountId, accountSecurityStamp, "new@example.com");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_ADJUST_EMAIL_CHANGE_CLEANUP_FAILED");
    }

    [Fact]
    public async Task CompleteEmailChange_hashes_raw_token_before_repository_call()
    {
        var harness = CreateServiceHarness();
        string? capturedHash = null;
        harness.AccountRepo.CompleteEmailChange(Arg.Do<string>(hash => capturedHash = hash))
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_SUCCEEDED", Guid.NewGuid())));

        AccountAdjustResult? result = await harness.Service.CompleteEmailChange("raw-token");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        capturedHash.ShouldBe(SecretHashUtility.HashToken("raw-token"));
        capturedHash.ShouldNotBe("raw-token");
    }


    [Fact]
    public async Task CompleteEmailChange_oversized_token_returns_mismatch_without_repository_call()
    {
        var harness = CreateServiceHarness();
        string verifyToken = new('x', AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength + 1);

        AccountAdjustResult? result = await harness.Service.CompleteEmailChange(verifyToken);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_ADJUST_TOKEN_MISMATCH");
        await harness.AccountRepo.DidNotReceive().CompleteEmailChange(Arg.Any<string>());
    }

    [Fact]
    public async Task RequestAccountDelete_hashes_token_and_passphrase_before_repository_call_and_sends_verify_url()
    {
        var harness = CreateServiceHarness();
        string? capturedPassPhraseHash = null;
        string? capturedDeleteTokenHash = null;
        Instant? capturedExpiration = null;
        string? emailedVerificationUrl = null;
        string? emailedVerificationSequence = null;
        Period? capturedRequestCooldown = null;
        Period? capturedRequestWindow = null;
        short? capturedMaxRequestsPerWindow = null;
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();

        harness.AccountRepo.RequestAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Do<string>(hash => capturedPassPhraseHash = hash),
                Arg.Do<string>(hash => capturedDeleteTokenHash = hash),
                Arg.Do<Instant>(expiration => capturedExpiration = expiration),
                Arg.Do<Period>(period => capturedRequestCooldown = period),
                Arg.Do<Period>(period => capturedRequestWindow = period),
                Arg.Do<short>(max => capturedMaxRequestsPerWindow = max))
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.PASS_PHRASE, "reader@example.com")));
        harness.SmtpService.DeleteAccountTwoStepLetter(
                "reader@example.com",
                harness.EmailSubjectSettings.AccountDeleteVerify,
                Arg.Do<string>(url => emailedVerificationUrl = url),
                Arg.Do<string>(sequence => emailedVerificationSequence = sequence))
            .Returns(Task.FromResult<bool?>(true));

        AccountDeleteCommandResult? result = await harness.Service.RequestAccountDelete(accountId, accountSecurityStamp, "delete me");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_DELETE_PENDING");
        result.Workflow.ShouldBe(DeletionWorkflow.PASS_PHRASE);
        capturedPassPhraseHash.ShouldNotBeNullOrWhiteSpace();
        capturedPassPhraseHash.ShouldNotBe("delete me");
        capturedPassPhraseHash.ShouldNotBe(SecretHashUtility.HashToken("delete me"));
        harness.UserSecretHasher.VerifyUserSecret("delete me", capturedPassPhraseHash!).ShouldBeTrue();
        capturedDeleteTokenHash.ShouldNotBeNullOrWhiteSpace();
        capturedDeleteTokenHash!.Length.ShouldBe(64);
        capturedExpiration.ShouldNotBeNull();
        capturedRequestCooldown.ShouldBe(Period.FromMinutes(15));
        capturedRequestWindow.ShouldBe(Period.FromHours(24));
        capturedMaxRequestsPerWindow.ShouldBe((short)8);
        emailedVerificationUrl.ShouldNotBeNullOrWhiteSpace();
        emailedVerificationUrl.ShouldStartWith("http://localhost.test/account/wipeout/verify?payload=");
        emailedVerificationUrl.ShouldNotContain(capturedDeleteTokenHash);
        emailedVerificationSequence.ShouldNotBeNullOrWhiteSpace();
        SecretHashUtility.HashToken(emailedVerificationSequence!).ShouldBe(capturedDeleteTokenHash);
    }

    [Fact]
    public async Task RequestAccountDelete_without_passphrase_stores_null_passphrase_hash()
    {
        var harness = CreateServiceHarness();
        string? capturedPassPhraseHash = "sentinel";
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();

        harness.AccountRepo.RequestAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Do<string?>(hash => capturedPassPhraseHash = hash),
                Arg.Any<string>(),
                Arg.Any<Instant>(),
                Arg.Any<Period>(),
                Arg.Any<Period>(),
                Arg.Any<short>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.ONETIME, "reader@example.com")));
        harness.SmtpService.DeleteAccountTwoStepLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(true));

        AccountDeleteCommandResult? result = await harness.Service.RequestAccountDelete(accountId, accountSecurityStamp, null);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        capturedPassPhraseHash.ShouldBeNull();
    }

    [Fact]
    public async Task RequestAccountDelete_email_failure_cancels_pending_request_and_returns_delivery_failed()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? capturedDeleteTokenHash = null;
        harness.AccountRepo.RequestAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Any<string?>(),
                Arg.Do<string>(hash => capturedDeleteTokenHash = hash),
                Arg.Any<Instant>(),
                Arg.Any<Period>(),
                Arg.Any<Period>(),
                Arg.Any<short>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.ONETIME, "reader@example.com")));
        harness.SmtpService.DeleteAccountTwoStepLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));
        harness.AccountRepo.CancelAccountDeleteRequest(accountId, accountSecurityStamp, Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_REQUEST_CANCELLED", DeletionWorkflow.ONETIME, "reader@example.com")));

        AccountDeleteCommandResult? result = await harness.Service.RequestAccountDelete(accountId, accountSecurityStamp, null);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED");
        capturedDeleteTokenHash.ShouldNotBeNullOrWhiteSpace();
        await harness.AccountRepo.Received(1).CancelAccountDeleteRequest(accountId, accountSecurityStamp, capturedDeleteTokenHash!);
    }

    [Fact]
    public async Task RequestAccountDelete_email_exception_cancels_pending_request_and_returns_delivery_failed()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? capturedDeleteTokenHash = null;
        harness.AccountRepo.RequestAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Any<string?>(),
                Arg.Do<string>(hash => capturedDeleteTokenHash = hash),
                Arg.Any<Instant>(),
                Arg.Any<Period>(),
                Arg.Any<Period>(),
                Arg.Any<short>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.ONETIME, "reader@example.com")));
        harness.SmtpService.DeleteAccountTwoStepLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromException<bool?>(new InvalidOperationException("smtp failed")));
        harness.AccountRepo.CancelAccountDeleteRequest(accountId, accountSecurityStamp, Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_REQUEST_CANCELLED", DeletionWorkflow.ONETIME, "reader@example.com")));

        AccountDeleteCommandResult? result = await harness.Service.RequestAccountDelete(accountId, accountSecurityStamp, null);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_DELETE_EMAIL_DELIVERY_FAILED");
        capturedDeleteTokenHash.ShouldNotBeNullOrWhiteSpace();
        await harness.AccountRepo.Received(1).CancelAccountDeleteRequest(accountId, accountSecurityStamp, capturedDeleteTokenHash!);
    }

    [Fact]
    public async Task RequestAccountDelete_cleanup_failure_returns_cleanup_failed()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.AccountRepo.RequestAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Any<string?>(),
                Arg.Any<string>(),
                Arg.Any<Instant>(),
                Arg.Any<Period>(),
                Arg.Any<Period>(),
                Arg.Any<short>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.ONETIME, "reader@example.com")));
        harness.SmtpService.DeleteAccountTwoStepLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));
        harness.AccountRepo.CancelAccountDeleteRequest(accountId, accountSecurityStamp, Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(false, "ACCOUNT_DELETE_TOKEN_MISMATCH")));

        AccountDeleteCommandResult? result = await harness.Service.RequestAccountDelete(accountId, accountSecurityStamp, null);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_DELETE_REQUEST_CLEANUP_FAILED");
    }


    [Fact]
    public async Task VerifyAccountDeleteToken_hashes_raw_token_before_repository_call()
    {
        var harness = CreateServiceHarness();
        string? capturedDeleteTokenHash = null;
        harness.AccountRepo.VerifyDeleteAccountToken(Arg.Do<string>(hash => capturedDeleteTokenHash = hash))
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_VERIFIED", DeletionWorkflow.ONETIME)));

        AccountDeleteCommandResult? result = await harness.Service.VerifyAccountDeleteToken("raw-delete-token");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_DELETE_VERIFIED");
        capturedDeleteTokenHash.ShouldNotBeNullOrWhiteSpace();
        capturedDeleteTokenHash.ShouldBe(SecretHashUtility.HashToken("raw-delete-token"));
        capturedDeleteTokenHash.ShouldNotBe("raw-delete-token");
    }

    [Fact]
    public async Task VerifyAccountDeleteToken_blank_token_returns_mismatch_without_repository_call()
    {
        var harness = CreateServiceHarness();

        AccountDeleteCommandResult? result = await harness.Service.VerifyAccountDeleteToken("   ");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_DELETE_TOKEN_MISMATCH");
        await harness.AccountRepo.DidNotReceive().VerifyDeleteAccountToken(Arg.Any<string>());
    }

    [Fact]
    public async Task FinalizeAccountDelete_hashes_token_but_passes_raw_passphrase_to_repository_for_argon2id_verification()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? capturedDeleteTokenHash = null;
        string? capturedPassPhrase = null;
        short? capturedMaxFailedFinalizeAttempts = null;
        Period? capturedFinalizeLockout = null;
        harness.AccountRepo.FinalizeAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Do<string>(hash => capturedDeleteTokenHash = hash),
                Arg.Do<string?>(rawSecret => capturedPassPhrase = rawSecret),
                Arg.Do<short>(max => capturedMaxFailedFinalizeAttempts = max),
                Arg.Do<Period>(period => capturedFinalizeLockout = period))
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED", DeletionWorkflow.NONE, null, accountId)));

        AccountDeleteCommandResult? result = await harness.Service.FinalizeAccountDelete(accountId, accountSecurityStamp, "raw-delete-token", "secret");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_DELETE_SUCCEEDED");
        capturedDeleteTokenHash.ShouldBe(SecretHashUtility.HashToken("raw-delete-token"));
        capturedPassPhrase.ShouldBe("secret");
        capturedMaxFailedFinalizeAttempts.ShouldBe((short)5);
        capturedFinalizeLockout.ShouldBe(Period.FromMinutes(30));
    }

    [Fact]
    public async Task FinalizeAccountDelete_without_passphrase_passes_null_secret()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.AccountRepo.FinalizeAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Any<string>(),
                Arg.Is<string?>(value => value == null),
                Arg.Any<short>(),
                Arg.Any<Period>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED", DeletionWorkflow.NONE, null, accountId)));

        AccountDeleteCommandResult? result = await harness.Service.FinalizeAccountDelete(accountId, accountSecurityStamp, "raw-delete-token", null);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        await harness.AccountRepo.Received(1).FinalizeAccountDelete(accountId, accountSecurityStamp, Arg.Any<string>(), Arg.Is<string?>(value => value == null), Arg.Any<short>(), Arg.Any<Period>());
    }

    [Fact]
    public async Task PurgeExpiredDeleteStandby_passes_current_moment_to_repository()
    {
        var harness = CreateServiceHarness();
        Instant? capturedMoment = null;
        harness.AccountRepo.PurgeExpiredDeleteStandby(Arg.Do<Instant>(moment => capturedMoment = moment))
            .Returns(Task.FromResult<AccountDeletePurgeResult?>(new AccountDeletePurgeResult(true, "ACCOUNT_DELETE_PURGE_SUCCEEDED", 2)));

        AccountDeletePurgeResult? result = await harness.Service.PurgeExpiredDeleteStandby();

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_DELETE_PURGE_SUCCEEDED");
        result.DeletedCount.ShouldBe(2);
        capturedMoment.ShouldNotBeNull();
    }

    [Fact]
    public async Task PurgeExpiredAccountEmailChangeRequests_passes_current_moment_to_repository()
    {
        var harness = CreateServiceHarness();
        Instant? capturedMoment = null;
        harness.AccountRepo.PurgeExpiredAccountEmailChangeRequests(Arg.Do<Instant>(moment => capturedMoment = moment))
            .Returns(Task.FromResult<AccountEmailChangePurgeResult?>(new AccountEmailChangePurgeResult(true, "ACCOUNT_ADJUST_PURGE_SUCCEEDED", 3)));

        AccountEmailChangePurgeResult? result = await harness.Service.PurgeExpiredAccountEmailChangeRequests();

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_ADJUST_PURGE_SUCCEEDED");
        result.DeletedCount.ShouldBe(3);
        capturedMoment.ShouldNotBeNull();
    }


    [Fact]
    public async Task SetupUserAccount_smtp_exception_returns_pending_verification_so_resend_can_recover()
    {
        var harness = CreateServiceHarness();
        harness.AccountRepo.SetupAccount(Arg.Any<Account>(), Arg.Any<string>(), Arg.Any<Period>(), AccountSetupAction.EMAIL)
            .Returns(Task.FromResult<(long?, HttpMessage, string?)>((7, HttpMessage.ACCOUNT_CREATION_SUCCESSED, null)));
        harness.AccountRepo.StartAccountVerification(Arg.Any<Guid>(), 7).Returns(Task.FromResult<bool?>(true));
        harness.SmtpService.VerificationLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("smtp failed")));

        HttpMessage result = await harness.Service.SetupUserAccount(
            "reader@example.com",
            null,
            "ValidPassword1!",
            Country.USA,
            SystemClock.Instance.GetCurrentInstant(),
            AccountSetupAction.EMAIL);

        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
    }

    [Fact]
    public async Task ResendAccountVerification_smtp_exception_keeps_verification_pending()
    {
        var harness = CreateServiceHarness();
        harness.AccountRepo.ResendAccountVerification("reader@example.com", Arg.Any<string>(), Arg.Any<Period>())
            .Returns(Task.FromResult<AccountVerificationResendResult?>(new AccountVerificationResendResult(true, "VERIFICATION_RESEND_STARTED", "reader@example.com")));
        harness.SmtpService.ResendVerifyLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(_ => Task.FromException<bool?>(new InvalidOperationException("smtp failed")));

        HttpMessage result = await harness.Service.ResendAccountVerification("reader@example.com");

        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);
    }

    private static AccountServiceHarness CreateServiceHarness()
    {
        var accountRepo = Substitute.For<IAccountRepo>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        var activeUserCache = Substitute.For<IActiveUserCacheService>();
        var jwtUtility = Substitute.For<IJsonWebTokenUtility>();
        var twoFactorService = Substitute.For<ITwoFactorAuthenticateService>();
        var smtpService = Substitute.For<ISMTPService>();
        var loginSettings = new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            Argon2Iterations = 1,
            Argon2MemoryUsePer = 8192
        };
        var registrationSettings = new RegistrationSettings
        {
            MinUsernameLength = 3,
            MaxUsernameLength = 30,
            MinPasswordLength = 8,
            MaxPasswordLength = 128,
            MaxEmailAddressLength = 255,
            AccountMetaDataRetries = 3,
            VerifyAccountPeriodWeeks = 0,
            VerifyAccountPeriodDays = 1,
            VerifyAccountPeriodHours = 0,
            EmailChangeVerifyPeriodWeeks = 0,
            EmailChangeVerifyPeriodDays = 1,
            EmailChangeVerifyPeriodHours = 0,
            AccountDeleteTokenPeriodWeeks = 0,
            AccountDeleteTokenPeriodDays = 1,
            AccountDeleteTokenPeriodHours = 0,
            AccountVerificationBaseUrl = "http://localhost.test",
            AccountEmailChangeVerificationBaseUrl = "http://localhost.test",
            AccountDeleteVerifyBaseUrl = "http://localhost.test",
            DeleteRequestCooldownMinutes = 15,
            DeleteRequestWindowHours = 24,
            DeleteMaxRequestsPerWindow = 8,
            DeleteMaxFinalizeFailures = 5,
            DeleteFinalizeLockoutMinutes = 30
        };
        var userSecretHasher = new Argon2idUserSecretHasher(Options.Create(loginSettings));

        var emailSubjectSettings = new EmailSubjectSettings
        {
            AccountVerify = "Verify your account",
            AccountVerifyResend = "Resend verification",
            AccountEmailChangeVerify = "Verify new email",
            AccountDeleteVerify = "Verify deletion",
            TwoFactorSetup = "Setup 2FA",
            TwoFactorKeyOutbound = "2FA code",
            TwoFactorDelete = "Delete 2FA"
        };

        var service = new AccountService(
            accountRepo,
            smtpService,
            Options.Create(loginSettings),
            Options.Create(registrationSettings),
            Options.Create(emailSubjectSettings),
            userSecretHasher);

        return new AccountServiceHarness(service, accountRepo, smtpService, emailSubjectSettings, userSecretHasher);
    }

    private sealed record AccountServiceHarness(
        AccountService Service,
        IAccountRepo AccountRepo,
        ISMTPService SmtpService,
        EmailSubjectSettings EmailSubjectSettings,
        IUserSecretHasher UserSecretHasher);
}
