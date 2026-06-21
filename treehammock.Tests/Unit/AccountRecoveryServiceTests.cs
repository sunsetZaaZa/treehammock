using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Models.Recovery;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.RiggingSupport.Enum;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AccountRecoveryServiceTests
{
    [Fact]
    public async Task StartRecovery_generates_backend_unlock_token_persists_it_with_lockout_snapshot_and_sends_it_to_locked_account_email()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();
        string? persistedToken = null;
        string? emailedBody = null;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant unlockWhen = now.Plus(Duration.FromMinutes(30));

        harness.Repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(LockedLookup(accountId, securityStamp, unlockWhen)));

        harness.Repo.BeginUnlock(
                accountId,
                Arg.Do<string>(token => persistedToken = token),
                now,
                Arg.Any<Instant>(),
                AccountRecovery_Status.STANDBY,
                AccountUnlockDeliveryMethod.EMAIL,
                securityStamp,
                unlockWhen)
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STANDBY));

        harness.SmtpService.AccountUnlockLetter("reader@example.com", "Unlock your Treehammock account", Arg.Do<string>(token => emailedBody = $"unlock:{token}"))
            .Returns(Task.FromResult<bool?>(true));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com"),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        persistedToken.ShouldNotBeNull();
        persistedToken!.Length.ShouldBeGreaterThan(20);
        emailedBody!.ShouldContain(persistedToken);
        emailedBody!.ShouldContain("unlock");

        await harness.Repo.Received(1).BeginUnlock(
            accountId,
            Arg.Any<string>(),
            now,
            Arg.Any<Instant>(),
            AccountRecovery_Status.STANDBY,
            AccountUnlockDeliveryMethod.EMAIL,
            securityStamp,
            unlockWhen);
    }

    [Fact]
    public async Task StartRecovery_returns_generic_pending_for_unknown_or_unlocked_identifier_without_sending_email()
    {
        var harness = CreateHarness();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.Repo.LookupLockedAccount("missing@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(new AccountRecoveryLookupResult(false, "ACCOUNT_UNLOCK_NOT_LOCKED", null, null, null, null, null, null)));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("missing@example.com"),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        await harness.SmtpService.DidNotReceive().AccountUnlockLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task StartRecovery_returns_generic_pending_when_lockout_snapshot_is_missing()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();

        harness.Repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(new AccountRecoveryLookupResult(true, "ACCOUNT_UNLOCK_ACCOUNT_FOUND", accountId, "reader@example.com", null, null, null, null)));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com"),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        await harness.Repo.DidNotReceive().BeginUnlock(
            Arg.Any<Guid>(),
            Arg.Any<string>(),
            Arg.Any<Instant>(),
            Arg.Any<Instant>(),
            Arg.Any<AccountRecovery_Status>(),
            Arg.Any<AccountUnlockDeliveryMethod>(),
            Arg.Any<Guid>(),
            Arg.Any<Instant>());
    }

    [Fact]
    public async Task StartRecovery_returns_generic_pending_when_begin_detects_stale_lockout_snapshot()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant unlockWhen = now.Plus(Duration.FromMinutes(30));

        harness.Repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(LockedLookup(accountId, securityStamp, unlockWhen)));

        harness.Repo.BeginUnlock(
                accountId,
                Arg.Any<string>(),
                now,
                Arg.Any<Instant>(),
                AccountRecovery_Status.STANDBY,
                AccountUnlockDeliveryMethod.EMAIL,
                securityStamp,
                unlockWhen)
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STALE_LOCKOUT));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com"),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        await harness.SmtpService.DidNotReceive().AccountUnlockLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task StartRecovery_cancels_pending_unlock_token_and_returns_generic_pending_when_email_delivery_fails()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();
        string? persistedToken = null;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant unlockWhen = now.Plus(Duration.FromMinutes(30));

        harness.Repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(LockedLookup(accountId, securityStamp, unlockWhen)));

        harness.Repo.BeginUnlock(
                accountId,
                Arg.Do<string>(token => persistedToken = token),
                now,
                Arg.Any<Instant>(),
                AccountRecovery_Status.STANDBY,
                AccountUnlockDeliveryMethod.EMAIL,
                securityStamp,
                unlockWhen)
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STANDBY));

        harness.SmtpService.AccountUnlockLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));

        harness.Repo.CancelUnlock(accountId, Arg.Any<string>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.CANCELED));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com"),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        await harness.Repo.Received(1).CancelUnlock(accountId, persistedToken!);
    }


    [Fact]
    public async Task StartRecovery_returns_generic_pending_when_delivery_fails_even_if_cleanup_fails()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant unlockWhen = now.Plus(Duration.FromMinutes(30));

        harness.Repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(LockedLookup(accountId, securityStamp, unlockWhen)));

        harness.Repo.BeginUnlock(
                accountId,
                Arg.Any<string>(),
                now,
                Arg.Any<Instant>(),
                AccountRecovery_Status.STANDBY,
                AccountUnlockDeliveryMethod.EMAIL,
                securityStamp,
                unlockWhen)
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STANDBY));

        harness.SmtpService.AccountUnlockLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
            .Returns(Task.FromResult<bool?>(false));

        harness.Repo.CancelUnlock(accountId, Arg.Any<string>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.BAD_VERIFY));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com"),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        await harness.Repo.Received(1).CancelUnlock(accountId, Arg.Any<string>());
    }

    [Fact]
    public async Task StartRecovery_can_deliver_unlock_token_by_sms_when_verified_sms_destination_exists()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();
        string? persistedToken = null;
        string? smsToken = null;
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant unlockWhen = now.Plus(Duration.FromMinutes(30));

        harness.Repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(new AccountRecoveryLookupResult(
                true,
                "ACCOUNT_UNLOCK_ACCOUNT_FOUND",
                accountId,
                "reader@example.com",
                "5555550101",
                "1",
                securityStamp,
                unlockWhen)));

        harness.Repo.BeginUnlock(
                accountId,
                Arg.Do<string>(token => persistedToken = token),
                now,
                Arg.Any<Instant>(),
                AccountRecovery_Status.STANDBY,
                AccountUnlockDeliveryMethod.SMS,
                securityStamp,
                unlockWhen)
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STANDBY));

        harness.SmsSender.SendCode("+15555550101", Arg.Do<string>(token => smsToken = token))
            .Returns(Task.FromResult(true));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com", AccountUnlockDeliveryMethod.SMS),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        smsToken.ShouldBe(persistedToken);
        await harness.Repo.Received(1).BeginUnlock(
            accountId,
            Arg.Any<string>(),
            now,
            Arg.Any<Instant>(),
            AccountRecovery_Status.STANDBY,
            AccountUnlockDeliveryMethod.SMS,
            securityStamp,
            unlockWhen);
        await harness.SmtpService.DidNotReceive().AccountUnlockLetter(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());
    }

    [Fact]
    public async Task StartRecovery_returns_generic_pending_without_persisting_when_sms_destination_is_missing()
    {
        var harness = CreateHarness();
        Guid accountId = Guid.NewGuid();
        Guid securityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant unlockWhen = now.Plus(Duration.FromMinutes(30));

        harness.Repo.LookupLockedAccount("reader@example.com", now)
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(new AccountRecoveryLookupResult(
                true,
                "ACCOUNT_UNLOCK_ACCOUNT_FOUND",
                accountId,
                "reader@example.com",
                null,
                null,
                securityStamp,
                unlockWhen)));

        AccountRecoveryStartResult result = await harness.Service.StartRecovery(
            new AccountRecoveryRequest("reader@example.com", AccountUnlockDeliveryMethod.SMS),
            now);

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.PendingCode);
        await harness.Repo.DidNotReceive().BeginUnlock(
            Arg.Any<Guid>(),
            Arg.Any<string>(),
            Arg.Any<Instant>(),
            Arg.Any<Instant>(),
            Arg.Any<AccountRecovery_Status>(),
            Arg.Any<AccountUnlockDeliveryMethod>(),
            Arg.Any<Guid>(),
            Arg.Any<Instant>());
        await harness.SmsSender.DidNotReceive().SendCode(Arg.Any<string>(), Arg.Any<string>());
    }


    [Fact]
    public async Task VerifyRecovery_throttles_by_token_before_sql_when_unlock_verify_counter_is_exhausted()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(
                Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountUnlock && key.Dimension == AbuseCounterDimension.TokenFingerprint),
                Arg.Any<AbuseCounterLimit>(),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 6,
                Limit: 5,
                Window: TimeSpan.FromMinutes(15),
                RetryAfter: TimeSpan.FromMinutes(5),
                ReasonCode: AbuseReasonCodes.CounterLimitExceeded)));
        var harness = CreateHarness(store);

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded);
        await harness.Repo.DidNotReceiveWithAnyArgs().VerifyUnlock(default!);
    }

    [Fact]
    public async Task VerifyRecovery_throttles_by_ip_before_sql_when_ip_counter_is_exhausted()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                AbuseCounterKey key = call.ArgAt<AbuseCounterKey>(0);
                if (key.Dimension == AbuseCounterDimension.IpFingerprint)
                {
                    return Task.FromResult(new CounterDecision(
                        Allowed: false,
                        CurrentCount: 26,
                        Limit: 25,
                        Window: TimeSpan.FromMinutes(15),
                        RetryAfter: TimeSpan.FromMinutes(10),
                        ReasonCode: AbuseReasonCodes.CounterLimitExceeded));
                }

                AbuseCounterLimit limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: true,
                    CurrentCount: 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: null,
                    ReasonCode: null));
            });
        var harness = CreateHarness(store);

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded);
        await harness.Repo.DidNotReceiveWithAnyArgs().VerifyUnlock(default!);
    }

    [Fact]
    public async Task VerifyRecovery_counter_store_unavailable_fails_closed_before_sql()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new CounterDecision(
                Allowed: false,
                CurrentCount: 0,
                Limit: 5,
                Window: TimeSpan.FromMinutes(15),
                RetryAfter: null,
                ReasonCode: AbuseReasonCodes.CounterStoreUnavailable)));
        var harness = CreateHarness(store);

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AbuseReasonCodes.CounterStoreUnavailable);
        await harness.Repo.DidNotReceiveWithAnyArgs().VerifyUnlock(default!);
    }

    [Fact]
    public async Task VerifyRecovery_resets_token_and_ip_counters_after_successful_unlock()
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                AbuseCounterLimit limit = call.ArgAt<AbuseCounterLimit>(1);
                return Task.FromResult(new CounterDecision(
                    Allowed: true,
                    CurrentCount: 1,
                    Limit: limit.MaxAttempts,
                    Window: limit.Window,
                    RetryAfter: null,
                    ReasonCode: null));
            });
        store.ResetAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<CancellationToken>())
            .Returns(Task.CompletedTask);
        var harness = CreateHarness(store);
        harness.Repo.VerifyUnlock("token-123")
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.COMPLETE));

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.VerifiedCode);
        await store.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountUnlock && key.Dimension == AbuseCounterDimension.TokenFingerprint),
            Arg.Any<CancellationToken>());
        await store.Received(1).ResetAsync(
            Arg.Is<AbuseCounterKey>(key => key.Feature == AbuseFeature.AccountUnlock && key.Dimension == AbuseCounterDimension.IpFingerprint),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task VerifyRecovery_maps_complete_status_to_unlock_verified_result()
    {
        var harness = CreateHarness();
        harness.Repo.VerifyUnlock("token-123")
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.COMPLETE));

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeTrue();
        result.Code.ShouldBe(AccountRecoveryService.VerifiedCode);
    }

    [Fact]
    public async Task VerifyRecovery_maps_stale_lockout_snapshot_to_token_mismatch()
    {
        var harness = CreateHarness();
        harness.Repo.VerifyUnlock("token-123")
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STALE_LOCKOUT));

        AccountRecoveryVerifyResult result = await harness.Service.VerifyRecovery(new AccountRecoveryVerifyRequest("token-123"));

        result.Result.ShouldBeFalse();
        result.Code.ShouldBe(AccountRecoveryService.TokenMismatchCode);
    }

    private static AccountRecoveryLookupResult LockedLookup(Guid accountId, Guid securityStamp, Instant unlockWhen)
    {
        return new AccountRecoveryLookupResult(
            true,
            "ACCOUNT_UNLOCK_ACCOUNT_FOUND",
            accountId,
            "reader@example.com",
            "+15555550101",
            null,
            securityStamp,
            unlockWhen);
    }

    private static AccountRecoveryHarness CreateHarness(IAbuseCounterStore? abuseCounterStore = null)
    {
        var repo = Substitute.For<IAccountRecoveryRepo>();
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        var subjects = Options.Create(new EmailSubjectSettings { AccountUnlock = "Unlock your Treehammock account" });
        var httpContextAccessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext()
        };
        httpContextAccessor.HttpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("203.0.113.42");

        var service = new AccountRecoveryService(
            repo,
            smtp,
            sms,
            subjects,
            NullLogger<AccountRecoveryService>.Instance,
            NullDeliveryAbuseThrottleService.Instance,
            new AccountUnlockAbuseCounterKeyFactory(),
            abuseCounterStore,
            Options.Create(new AbuseControlSettings()),
            httpContextAccessor);
        return new AccountRecoveryHarness(service, repo, smtp, sms, abuseCounterStore);
    }

    private sealed record AccountRecoveryHarness(
        AccountRecoveryService Service,
        IAccountRecoveryRepo Repo,
        ISMTPService SmtpService,
        ISmsSender SmsSender,
        IAbuseCounterStore? AbuseCounterStore);
}
