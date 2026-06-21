namespace treehammock.Rigging.Sidewalk;

public enum ProviderDeliveryStatus
{
    Sent,
    Disabled,
    ConfigurationMissing,
    InvalidRequest,
    Rejected,
    RateLimited,
    ProviderUnavailable,
    Failed
}

public sealed record ProviderDeliveryResult(
    ProviderDeliveryStatus Status,
    string Provider,
    string? ProviderMessageId = null,
    string? FailureCode = null)
{
    public bool Succeeded => Status == ProviderDeliveryStatus.Sent;

    public static ProviderDeliveryResult Sent(string provider, string providerMessageId) =>
        new(ProviderDeliveryStatus.Sent, provider, providerMessageId);

    public static ProviderDeliveryResult Disabled(string provider) =>
        new(ProviderDeliveryStatus.Disabled, provider, FailureCode: "PROVIDER_DISABLED");

    public static ProviderDeliveryResult ConfigurationMissing(string provider, string settingName) =>
        new(ProviderDeliveryStatus.ConfigurationMissing, provider, FailureCode: $"CONFIGURATION_MISSING:{settingName}");

    public static ProviderDeliveryResult InvalidRequest(string provider, string reason) =>
        new(ProviderDeliveryStatus.InvalidRequest, provider, FailureCode: reason);

    public static ProviderDeliveryResult Rejected(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.Rejected, provider, FailureCode: reason ?? "REJECTED");

    public static ProviderDeliveryResult RateLimited(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.RateLimited, provider, FailureCode: reason ?? "RATE_LIMITED");

    public static ProviderDeliveryResult ProviderUnavailable(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.ProviderUnavailable, provider, FailureCode: reason ?? "PROVIDER_UNAVAILABLE");

    public static ProviderDeliveryResult Failed(string provider, string? reason = null) =>
        new(ProviderDeliveryStatus.Failed, provider, FailureCode: reason ?? "FAILED");
}
