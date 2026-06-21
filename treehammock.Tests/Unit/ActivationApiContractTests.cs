using Shouldly;

namespace treehammock.Tests.Unit;

public class ActivationApiContractTests
{
    [Fact]
    public void Activations_controller_is_api_controller_not_mvc_view_shell()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));

        source.ShouldContain("class ActivationsController : ControllerBase");
        source.ShouldContain("[ApiController]");
        source.ShouldContain("[Route(\"activations\")]");
        source.ShouldContain("[HttpPost(\"place\")]");
        source.ShouldContain("[HttpPost(\"verify\")]");
        source.ShouldContain("[HttpPost(\"disable\")]");
        source.ShouldNotContain("return View();");
    }

    [Fact]
    public void Activation_creation_request_no_longer_accepts_client_supplied_code()
    {
        string source = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationCreation.cs"));

        source.ShouldNotContain("required string code");
        source.ShouldNotContain("string code");
    }

    [Fact]
    public void Activation_sql_returns_explicit_result_codes_for_stale_stamp_expired_and_code_mismatch()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("returns table(result boolean, code text, status smallint)");
        sql.ShouldContain("returns table(\n    result boolean,\n    code text,");
        sql.ShouldContain("ACCOUNT_SECURITY_STAMP_MISMATCH");
        sql.ShouldContain("ACTIVATION_EXPIRED");
        sql.ShouldContain("ACTIVATION_CODE_MISMATCH");
        sql.ShouldContain("ACTIVATION_EMAIL_MISMATCH");
    }

    [Fact]
    public void Activations_controller_maps_stale_stamp_to_401_and_expired_activation_to_410()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));

        source.ShouldContain("ActivationService.SecurityStampMismatchCode => StatusCodes.Status401Unauthorized");
        source.ShouldContain("ActivationService.ExpiredCode => StatusCodes.Status410Gone");
        source.ShouldContain("ActivationService.CodeMismatchCode");
        source.ShouldContain("AbuseReasonCodes.ActivationVerifyAttemptsExceeded => StatusCodes.Status429TooManyRequests");
        source.ShouldContain("AbuseReasonCodes.CounterStoreUnavailable or AbuseReasonCodes.CounterStoreTimeout => StatusCodes.Status503ServiceUnavailable");
        source.ShouldContain("StatusCodes.Status429TooManyRequests");
        source.ShouldContain("StatusCodes.Status503ServiceUnavailable");
        source.ShouldContain("StatusCodes.Status428PreconditionRequired");
    }

    [Fact]
    public void Activation_sql_stores_backend_supplied_code_instead_of_generating_one()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));
        int start = sql.IndexOf("create or replace function place_activation(", StringComparison.Ordinal);
        int end = sql.IndexOf("create or replace function cancel_activation_request(", StringComparison.Ordinal);
        string placeActivation = sql[start..end];

        placeActivation.ShouldContain("p_code text");
        placeActivation.ShouldContain("p_code,");
        placeActivation.ShouldNotContain("gen_random_uuid()::text");
    }


    [Fact]
    public void Activation_creation_validates_term_and_recycle_before_service_sql_contracts()
    {
        string controller = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));
        string service = File.ReadAllText(ProjectFile("Services", "ActivationService.cs"));
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        controller.ShouldContain("Enum.IsDefined(typeof(DayDuration), payload.term)");
        controller.ShouldContain("Enum.IsDefined(typeof(DurationRepeat), payload.recycle)");
        controller.ShouldContain("ActivationService.InvalidTermCode");
        controller.ShouldContain("ActivationService.InvalidRecycleCode");

        service.ShouldContain("public const string InvalidTermCode = \"ACTIVATION_INVALID_TERM\"");
        service.ShouldContain("public const string InvalidRecycleCode = \"ACTIVATION_INVALID_RECYCLE\"");
        service.ShouldContain("IsSupportedActivationTerm(request.term)");
        service.ShouldContain("IsSupportedActivationRecycle(request.recycle)");
        service.ShouldContain("throw new ArgumentOutOfRangeException");

        sql.ShouldContain("ACTIVATION_INVALID_TERM");
        sql.ShouldContain("ACTIVATION_INVALID_RECYCLE");
        sql.ShouldContain("p_term is null or p_term < 1 or p_term > 11");
        sql.ShouldContain("p_interval is null or p_interval < 0 or p_interval > 10");
    }


    [Fact]
    public void Activation_controller_rejects_unbounded_email_and_code_inputs()
    {
        string controller = File.ReadAllText(ProjectFile("Controllers", "ActivationsController.cs"));
        string creationModel = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationCreation.cs"));
        string detailsModel = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationDetails.cs"));
        string unsubscribeModel = File.ReadAllText(ProjectFile("Models", "Activation", "ActivationUnSubscribe.cs"));

        creationModel.ShouldContain("MaxEmailAddressLength = 1024");
        detailsModel.ShouldContain("MaxEmailAddressLength = 1024");
        detailsModel.ShouldContain("MaxCodeLength = 128");
        unsubscribeModel.ShouldContain("MaxEmailAddressLength = 1024");

        controller.ShouldContain("payload.emailAddress = payload.emailAddress?.Trim() ?? string.Empty;");
        controller.ShouldContain("payload.code = payload.code?.Trim() ?? string.Empty;");
        controller.ShouldContain("emailAddress must be no longer than");
        controller.ShouldContain("code must be no longer than");
    }

    private static string ProjectFile(params string[] relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return Path.Combine(new[] { directory.FullName }.Concat(relativePath).ToArray());
    }
}
