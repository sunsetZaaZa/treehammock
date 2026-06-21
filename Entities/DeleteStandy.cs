using NodaTime;
using System.Diagnostics.CodeAnalysis;

namespace treehammock.Entities;

public class DeleteStandy
{
    [SetsRequiredMembers]
    public DeleteStandy(Guid accountId, string passPhraseHash, Instant expiration, bool verified) =>
        (this.accountId, this.passPhraseHash, this.expiration, this.verified) =
        (accountId, passPhraseHash, expiration, verified);


    public required Guid accountId { get; set; }
    public string? passPhraseHash { get; set; }
    public string? deleteTokenHash { get; set; }
    public required Instant expiration { get; set; }
    public required bool verified { get; set; }
    public short requestedCount { get; set; }
    public Instant? lastRequestedAt { get; set; }
    public Instant? nextRequestAllowedAt { get; set; }
    public short failedFinalizeAttempts { get; set; }
    public Instant? finalizeLockedUntil { get; set; }
}
