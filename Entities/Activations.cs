namespace treehammock.Entities;

using treehammock.RiggingSupport.Enum;
using NodaTime;
using System.Diagnostics.CodeAnalysis;

public class Activations
{
    [SetsRequiredMembers]
    public Activations(Guid accountId, Instant createdOn, Duration term, Instant off, FeatureSet featureSet, string code,
                    ActivationStatus status)
    {
        (this.accountId, this.createdOn, this.term, this.off, this.featureSet, this.code, this.status) =
            (accountId, createdOn, term, off, featureSet, code, status);
    }

    [SetsRequiredMembers]
    public Activations(Guid accountId, Instant createdOn, Duration term, Instant off, FeatureSet featureSet, string code, 
                        ActivationStatus status, Instant? delayedStart) {
        (this.accountId, this.createdOn, this.term, this.off, this.featureSet, this.code, this.status, this.delayedStart) = 
            (accountId, createdOn, term, off, featureSet, code, status, delayedStart);
    }

    public required Guid accountId { get; set; }
    public required Instant createdOn { get; set; }
    public required Duration term { get; set; }
    public required Instant off { get; set; }
    public required FeatureSet featureSet { get; set; }
    public required string code { get; set; }
    public required ActivationStatus status { get; set; }
    public Instant? delayedStart { get; set; }
}