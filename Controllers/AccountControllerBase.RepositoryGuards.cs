using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Globalization;

using NodaTime;
using Geralt;
using treehammock.Rigging.Authorization.Attributes;
using treehammock.Models.Authentication;
using treehammock.Models.Account;
using treehammock.Repos;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Authorization;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Services;
using treehammock.RiggingSupport.Status;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.Entities;
using treehammock.Rigging.Config;
using treehammock.Rigging.Observability;
using treehammock.Rigging.Security;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Replay;
using treehammock.Models.Api;

namespace treehammock.Controllers;

public abstract partial class AccountControllerBase
{
    protected async Task<CredentialLookupResult?> SafeGetCredentials(AuthenticateLogin payload, AccountLoginAction action)
    {
        try
        {
            return await _accountRepo.GetCredentials(payload, action);
        }
        catch
        {
            return CredentialLookupResult.Failed();
        }
    }

    protected async Task<TwoFactorDetailsLookupResult?> SafeGetTwoFactorDetails(Guid accountId)
    {
        try
        {
            return await _accountRepo.GetTwoFactorDetails(accountId);
        }
        catch
        {
            return TwoFactorDetailsLookupResult.Failed();
        }
    }

    protected async Task<bool?> SafeSetLockOut(Guid accountId, short? loginFailures)
    {
        try
        {
            return await _accountRepo.SetLockOut(accountId, loginFailures);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeRemoveLockOut(Guid accountId)
    {
        try
        {
            return await _accountRepo.RemoveLockOut(accountId);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeSetLoginFailures(Guid accountId, int failures)
    {
        try
        {
            return await _accountRepo.SetLoginFailures(accountId, failures);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeSuccessfulLogin(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            return await _accountRepo.SuccessfulLogin(accountId, accountSecurityStamp);
        }
        catch
        {
            return null;
        }
    }


    protected async Task<bool?> SafeBeginTwoFactorSession(
        Guid accountId,
        Guid accountSecurityStamp,
        short? twoAuthUsage,
        string preAuthAccessTokenHash,
        Instant createdOn,
        Instant expiration)
    {
        try
        {
            return await _accountRepo.BeginTwoFactorSession(accountId, accountSecurityStamp, twoAuthUsage, preAuthAccessTokenHash, createdOn, expiration);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<TwoFactorChallengeCommandResult?> SafeRecordTwoFactorChallengeIssued(TwoFactorSession session, string hashedPreAuthToken, Instant moment)
    {
        try
        {
            return await _accountRepo.RecordTwoFactorChallengeIssued(
                session.accountId,
                session.accountSecurityStamp,
                hashedPreAuthToken,
                session.challengedMethod ?? TwoFactorAuthMethod.NONE,
                session.chosenDestination ?? 0,
                session.challengeCodeHash,
                session.challengeProviderTransactionId,
                session.challengeExpiration ?? session.expiration,
                session.nextChallengeAllowedAt ?? moment,
                (short)Math.Min(short.MaxValue, Math.Max(0, _loginSettings.TwoAuthRetryLimit)),
                moment,
                session.selectedConfiguration,
                session.state,
                session.requiredMethods,
                session.completedMethods,
                session.currentExpectedMethod,
                moment);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<TwoFactorChallengeCommandResult?> SafeCancelTwoFactorChallengeIssued(TwoFactorSession session, string hashedPreAuthToken, Instant moment)
    {
        try
        {
            if (session.challengedMethod == null || session.chosenDestination == null)
            {
                return null;
            }

            return await _accountRepo.CancelTwoFactorChallengeIssued(
                session.accountId,
                session.accountSecurityStamp,
                hashedPreAuthToken,
                session.challengedMethod.Value,
                session.chosenDestination.Value,
                session.challengeCodeHash,
                session.challengeProviderTransactionId,
                moment);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<TwoFactorChallengeCommandResult?> SafeRecordTwoFactorChallengeFailure(TwoFactorSession session, string hashedPreAuthToken, Instant moment)
    {
        try
        {
            return await _accountRepo.RecordTwoFactorChallengeFailure(
                session.accountId,
                session.accountSecurityStamp,
                hashedPreAuthToken,
                (short)Math.Min(short.MaxValue, Math.Max(0, _loginSettings.TwoAuthRetryLimit)),
                moment);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeSetTwoFactorSession(Guid accountId, Guid accountSecurityStamp, short? twoAuthUsage, string preAuthAccessTokenHash)
    {
        try
        {
            return await _accountRepo.Set2FASession(accountId, accountSecurityStamp, twoAuthUsage, preAuthAccessTokenHash);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeIsPendingTwoFactorSessionCurrent(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp)
    {
        try
        {
            return await _accountRepo.IsPendingTwoFactorSessionCurrent(accountId, expectedPreAuthAccessTokenHash, accountSecurityStamp);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeSuccessfulTwoFactorAuth(Guid accountId, string expectedPreAuthAccessTokenHash, Guid accountSecurityStamp)
    {
        try
        {
            return await _accountRepo.SuccessfulTwoFactorAuth(accountId, expectedPreAuthAccessTokenHash, accountSecurityStamp);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<DbCommandResult?> SafePromoteTwoFactorNewLogin(
        Guid accountId,
        string expectedPreAuthAccessTokenHash,
        Guid accountSecurityStamp,
        string newAccessTokenHash,
        Session newSession)
    {
        try
        {
            return await _accountRepo.PromoteTwoFactorNewLogin(
                accountId,
                expectedPreAuthAccessTokenHash,
                accountSecurityStamp,
                newAccessTokenHash,
                newSession);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<DbCommandResult?> SafePromoteTwoFactorRotationLogin(
        Guid accountId,
        string expectedPreAuthAccessTokenHash,
        Guid accountSecurityStamp,
        string expectedOldAccessTokenHash,
        string newAccessTokenHash,
        Session newSession)
    {
        try
        {
            return await _accountRepo.PromoteTwoFactorRotationLogin(
                accountId,
                expectedPreAuthAccessTokenHash,
                accountSecurityStamp,
                expectedOldAccessTokenHash,
                newAccessTokenHash,
                newSession);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<IntraMessage?> SafeSetSession(string hashedAccessToken, Session record)
    {
        try
        {
            return await _sessionRepo.SetSession(hashedAccessToken, record);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<SessionRotationResult?> SafeRotateActiveSession(Guid accountId, string expectedOldAccessTokenHash, string newAccessTokenHash, Session newSession)
    {
        try
        {
            return await _sessionRepo.RotateActiveSession(accountId, expectedOldAccessTokenHash, newAccessTokenHash, newSession);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<bool?> SafeExpireSession(string hashedAccessToken, Instant? newExpiration)
    {
        try
        {
            return await _sessionRepo.ExpireSession(hashedAccessToken, newExpiration);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<DbCommandResult?> SafeLogoutCurrentSession(Guid accountId, string hashedAccessToken, Guid accountSecurityStamp)
    {
        try
        {
            return await _sessionRepo.LogoutCurrentSession(accountId, hashedAccessToken, accountSecurityStamp);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountStampRotationResult?> SafeLogoutAllSessions(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            return await _sessionRepo.LogoutAllSessions(accountId, accountSecurityStamp);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<IReadOnlyList<AccountSessionSummary>?> SafeListActiveSessions(Guid accountId, Guid accountSecurityStamp, string currentAccessTokenHash)
    {
        try
        {
            return await _sessionRepo.ListActiveSessions(accountId, accountSecurityStamp, currentAccessTokenHash);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountAdjustResult?> SafeModifyUsername(Guid accountId, Guid accountSecurityStamp, string username)
    {
        try
        {
            return await _accountRepo.ModifyUsername(accountId, accountSecurityStamp, username);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountAdjustResult?> SafeRequestEmailChange(Guid accountId, Guid accountSecurityStamp, string newEmailAddress)
    {
        try
        {
            return await _accountService.RequestEmailChange(accountId, accountSecurityStamp, newEmailAddress);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountAdjustResult?> SafeCompleteEmailChange(string verifyKey)
    {
        try
        {
            return await _accountService.CompleteEmailChange(verifyKey);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountViewResult?> SafeViewAccount(Guid accountId, Guid accountSecurityStamp)
    {
        try
        {
            return await _accountRepo.ViewAccount(accountId, accountSecurityStamp);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountDeleteCommandResult?> SafeRequestAccountDelete(Guid accountId, Guid accountSecurityStamp, string? passPhrase)
    {
        try
        {
            return await _accountService.RequestAccountDelete(accountId, accountSecurityStamp, passPhrase);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountDeleteCommandResult?> SafeVerifyAccountDeleteToken(string deleteToken)
    {
        try
        {
            return await _accountService.VerifyAccountDeleteToken(deleteToken);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<AccountDeleteCommandResult?> SafeFinalizeAccountDelete(
        Guid accountId,
        Guid accountSecurityStamp,
        string deleteToken,
        string? passPhrase)
    {
        try
        {
            return await _accountService.FinalizeAccountDelete(accountId, accountSecurityStamp, deleteToken, passPhrase);
        }
        catch
        {
            return null;
        }
    }


    protected async Task<DbCommandResult?> SafeRevokeSessionForAccount(Guid accountId, Guid targetSessionId, Guid accountSecurityStamp, string currentAccessTokenHash)
    {
        try
        {
            return await _sessionRepo.RevokeSessionForAccount(accountId, targetSessionId, accountSecurityStamp, currentAccessTokenHash);
        }
        catch
        {
            return null;
        }
    }

    protected async Task<PendingSessionWriteResult> SafeSetPendingTwoFactorSession(string hashedPreAuthToken, TwoFactorSession session, TimeSpan ttl)
    {
        try
        {
            return new PendingSessionWriteResult(await _twoFactorSessionService.SetSession(hashedPreAuthToken, session, ttl));
        }
        catch
        {
            return new PendingSessionWriteResult(null, ExceptionThrown: true);
        }
    }

    protected async Task<PendingSessionRevokeResult> SafeRevokePendingTwoFactorSession(string hashedPreAuthToken)
    {
        try
        {
            return new PendingSessionRevokeResult(await _twoFactorSessionService.RevokeSession(hashedPreAuthToken));
        }
        catch
        {
            return new PendingSessionRevokeResult(false, ExceptionThrown: true);
        }
    }

    protected async Task<ActiveCacheWriteResult> SafeSetActiveSession(string hashedAccessToken, ActiveSession session, TimeSpan ttl)
    {
        try
        {
            return new ActiveCacheWriteResult(await _activeUserCacheService.SetSession(hashedAccessToken, session, ttl));
        }
        catch
        {
            return new ActiveCacheWriteResult(false, ExceptionThrown: true);
        }
    }

    protected async Task<ActiveSessionRevokeResult> SafeRevokeActiveSession(string hashedAccessToken)
    {
        try
        {
            return new ActiveSessionRevokeResult(await _activeUserCacheService.RevokeSession(hashedAccessToken));
        }
        catch
        {
            return new ActiveSessionRevokeResult(false, ExceptionThrown: true);
        }
    }

    protected ActiveSession BuildPromotedActiveSession(TwoFactorSession session, byte[] refreshToken, Instant moment, out Period cachePeriod)
    {
        Period sessionLifespan = BuildDatabaseSessionLifespan();
        Instant sessionExpiration = moment.Plus(sessionLifespan.ToDuration());
        Instant accessExpiration = ResolveAccessExpiration(moment, sessionExpiration, session.cutOff, out cachePeriod);

        return new ActiveSession(
            session.accountId,
            refreshToken,
            0,
            moment,
            sessionLifespan,
            accessExpiration,
            sessionExpiration,
            session.cutOff,
            session.features,
            accountSecurityStamp: session.accountSecurityStamp);
    }

}
