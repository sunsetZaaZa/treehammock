using System.Diagnostics.Metrics;
using System.Text;

using treehammock.Rigging.Abuse;

namespace treehammock.Rigging.Observability;

public static class AbuseOperationalEventNames
{
    public const string PolicyAllowed = "abuse.policy_allowed";
    public const string PolicyDenied = "abuse.policy_denied";
    public const string CooldownStarted = "abuse.cooldown_started";
    public const string CounterStoreTimeout = "abuse.counter_store_timeout";
    public const string CounterStoreFailed = "abuse.counter_store_failed";
    public const string DeliveryThrottled = "delivery.throttled";
    public const string LoginThrottled = "login.throttled";
    public const string PasswordResetThrottled = "password_reset.throttled";
    public const string TwoFactorThrottled = "two_factor.throttled";
    public const string CloudflareChallengeDetected = "cloudflare.challenge_detected";
    public const string CloudflareBotSignalHigh = "cloudflare.bot_signal_high";
    public const string OriginBypassDenied = "edge.origin_bypass_denied";
}

public static class AbuseMetricNames
{
    public const string PolicyDecisionsTotal = "treehammock_abuse_policy_decisions_total";
    public const string CooldownsStartedTotal = "treehammock_abuse_cooldowns_started_total";
    public const string CounterStoreFailuresTotal = "treehammock_abuse_counter_store_failures_total";
    public const string DeliveryThrottledTotal = "treehammock_delivery_throttled_total";
    public const string LoginThrottledTotal = "treehammock_login_throttled_total";
    public const string PasswordResetThrottledTotal = "treehammock_password_reset_throttled_total";
    public const string TwoFactorThrottledTotal = "treehammock_two_factor_throttled_total";
    public const string EdgeAbuseEventsTotal = "treehammock_edge_abuse_events_total";
}

public static class AbuseMetricLabels
{
    public const string Event = "event";
    public const string Feature = "feature";
    public const string Dimension = "dimension";
    public const string Outcome = "outcome";
    public const string Reason = "reason";
    public const string DeliveryMethod = "delivery_method";
    public const string Operation = "operation";
    public const string Dependency = "dependency";

    public static readonly IReadOnlySet<string> Allowed = new HashSet<string>(StringComparer.Ordinal)
    {
        Event,
        Feature,
        Dimension,
        Outcome,
        Reason,
        DeliveryMethod,
        Operation,
        Dependency
    };

    public static readonly IReadOnlySet<string> Forbidden = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "account_id",
        "accountId",
        "session_id",
        "sessionId",
        "challenge_id",
        "challengeId",
        "reset_id",
        "resetId",
        "emailAddress",
        "email",
        "phoneNumber",
        "phone",
        "username",
        "identifier",
        "token",
        "sensitiveActionToken",
        "setupId",
        "manualEntryKey",
        "otpauthUri",
        "accessToken",
        "refreshToken",
        "resetCode",
        "totpCode",
        "totpSecret",
        "password",
        "passwordHash",
        "ip",
        "ipAddress",
        "clientIp",
        "connectionString"
    };
}

public static class AbuseOperationalTelemetry
{
    public const string MeterName = "treehammock.abuse";
    public const string MeterVersion = "1.0.0";
    public const string DependencyDragonfly = "dragonfly";

    private static readonly Meter Meter = new(MeterName, MeterVersion);

    private static readonly Counter<long> PolicyDecisions = Meter.CreateCounter<long>(
        AbuseMetricNames.PolicyDecisionsTotal,
        unit: "decisions",
        description: "Abuse policy decisions by bounded feature, dimension, outcome, and reason.");

    private static readonly Counter<long> CooldownsStarted = Meter.CreateCounter<long>(
        AbuseMetricNames.CooldownsStartedTotal,
        unit: "cooldowns",
        description: "Abuse cooldown starts by bounded feature, dimension, and reason.");

    private static readonly Counter<long> CounterStoreFailures = Meter.CreateCounter<long>(
        AbuseMetricNames.CounterStoreFailuresTotal,
        unit: "failures",
        description: "Dragonfly abuse counter failures and timeouts by bounded operation and reason.");

    private static readonly Counter<long> DeliveryThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.DeliveryThrottledTotal,
        unit: "throttles",
        description: "Email/SMS delivery throttles by delivery method and reason.");

    private static readonly Counter<long> LoginThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.LoginThrottledTotal,
        unit: "throttles",
        description: "Login abuse throttles by bounded dimension and reason.");

    private static readonly Counter<long> PasswordResetThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.PasswordResetThrottledTotal,
        unit: "throttles",
        description: "Password-reset request/finalize throttles by bounded feature, dimension, and reason.");

    private static readonly Counter<long> TwoFactorThrottled = Meter.CreateCounter<long>(
        AbuseMetricNames.TwoFactorThrottledTotal,
        unit: "throttles",
        description: "Two-factor challenge throttles by bounded dimension and reason.");

    private static readonly Counter<long> EdgeAbuseEvents = Meter.CreateCounter<long>(
        AbuseMetricNames.EdgeAbuseEventsTotal,
        unit: "events",
        description: "Cloudflare/edge abuse-control observations by bounded event and outcome.");

    public static void RecordPolicyAllowed(AbuseFeature feature, AbuseCounterDimension dimension)
    {
        PolicyDecisions.Add(
            1,
            Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Outcome, "allowed"),
            Tag(AbuseMetricLabels.Reason, "none"));
    }

    public static void RecordPolicyDenied(
        AbuseFeature feature,
        AbuseCounterDimension dimension,
        string? reasonCode)
    {
        string reason = ReasonName(reasonCode);
        PolicyDecisions.Add(
            1,
            Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Outcome, "denied"),
            Tag(AbuseMetricLabels.Reason, reason));

        if (reason == AbuseReasonCodes.FailureCooldownActive.ToLowerInvariant())
        {
            RecordCooldownStarted(feature, dimension, reasonCode);
        }
    }

    public static void RecordCounterStoreFailure(string operation, string? reasonCode)
    {
        CounterStoreFailures.Add(
            1,
            Tag(AbuseMetricLabels.Dependency, DependencyDragonfly),
            Tag(AbuseMetricLabels.Operation, NormalizeTagValue(operation)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordCooldownStarted(
        AbuseFeature feature,
        AbuseCounterDimension dimension,
        string? reasonCode)
    {
        CooldownsStarted.Add(
            1,
            Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordDeliveryThrottled(string method, string? reasonCode)
    {
        DeliveryThrottled.Add(
            1,
            Tag(AbuseMetricLabels.DeliveryMethod, NormalizeDeliveryMethod(method)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordLoginThrottled(AbuseCounterDimension dimension, string? reasonCode)
    {
        LoginThrottled.Add(
            1,
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordPasswordResetThrottled(
        AbuseFeature feature,
        AbuseCounterDimension dimension,
        string? reasonCode)
    {
        PasswordResetThrottled.Add(
            1,
            Tag(AbuseMetricLabels.Feature, FeatureName(feature)),
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordTwoFactorThrottled(AbuseCounterDimension dimension, string? reasonCode)
    {
        TwoFactorThrottled.Add(
            1,
            Tag(AbuseMetricLabels.Dimension, DimensionName(dimension)),
            Tag(AbuseMetricLabels.Reason, ReasonName(reasonCode)));
    }

    public static void RecordEdgeAbuseEvent(string eventName, string outcome)
    {
        EdgeAbuseEvents.Add(
            1,
            Tag(AbuseMetricLabels.Event, NormalizeTagValue(eventName)),
            Tag(AbuseMetricLabels.Outcome, NormalizeTagValue(outcome)));
    }

    private static KeyValuePair<string, object?> Tag(string name, string value)
    {
        if (!AbuseMetricLabels.Allowed.Contains(name) || AbuseMetricLabels.Forbidden.Contains(name))
        {
            throw new ArgumentException("Abuse metric tag name is not allowed.", nameof(name));
        }

        return new KeyValuePair<string, object?>(name, NormalizeTagValue(value));
    }

    private static string FeatureName(AbuseFeature feature)
    {
        return feature.ToString().Trim().ToLowerInvariant();
    }

    private static string DimensionName(AbuseCounterDimension dimension)
    {
        return dimension.ToString().Trim().ToLowerInvariant();
    }

    private static string ReasonName(string? reasonCode)
    {
        return NormalizeTagValue(string.IsNullOrWhiteSpace(reasonCode) ? "none" : reasonCode);
    }

    private static string NormalizeDeliveryMethod(string? method)
    {
        string normalized = NormalizeTagValue(method);
        return normalized is "sms" or "phone" or "sms_key" ? "sms" : "email";
    }

    private static string NormalizeTagValue(string? value)
    {
        string normalized = string.IsNullOrWhiteSpace(value)
            ? "unknown"
            : value.Trim().ToLowerInvariant();

        var builder = new StringBuilder(normalized.Length);
        foreach (char ch in normalized)
        {
            builder.Append(char.IsLetterOrDigit(ch) || ch is '_' or '-' or '.' ? ch : '_');
        }

        return builder.ToString();
    }
}
