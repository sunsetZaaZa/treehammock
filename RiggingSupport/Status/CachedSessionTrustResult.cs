namespace treehammock.RiggingSupport.Status;

using NodaTime;

public enum CachedSessionTrustStatus
{
    Valid = 1,
    SessionNotFound = 2,
    AccountNotFound = 3,
    SecurityStampMismatch = 4,
    SessionExpired = 5,
    AccountSecurityStampMismatch = 6,
    Failed = 99
}

public sealed record CachedSessionTrustResult(
    CachedSessionTrustStatus Status,
    Instant? AccessExpiration = null,
    Instant? SessionExpiration = null,
    Instant? CutOff = null,
    Guid? SecurityStamp = null,
    Guid? AccountSecurityStamp = null,
    string? Code = null)
{
    public bool Succeeded => Status == CachedSessionTrustStatus.Valid;
}
