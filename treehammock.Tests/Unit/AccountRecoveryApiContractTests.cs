using Shouldly;

namespace treehammock.Tests.Unit;

public class AccountRecoveryApiContractTests
{
    [Fact]
    public void Account_unlock_controller_exposes_start_and_verify_token_endpoints()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "AccountRecoveryController.cs"));

        source.ShouldContain("class AccountRecoveryController : ControllerBase");
        source.ShouldContain("[ApiController]");
        source.ShouldContain("[AllowAnonymous]");
        source.ShouldContain("[Route(\"account/unlock\")]");
        source.ShouldContain("[HttpPost(\"start\")]");
        source.ShouldContain("[HttpPost(\"verify\")]");
        source.ShouldNotContain("[Authenticate]");
        source.ShouldNotContain("AccountRecovery_Topic");
        source.ShouldNotContain("AccountRecovery_Type");
    }


    [Fact]
    public void Account_unlock_verify_endpoint_advertises_abuse_replay_failure_status_codes()
    {
        string source = File.ReadAllText(ProjectFile("Controllers", "AccountRecoveryController.cs"));

        source.ShouldContain("StatusCodes.Status429TooManyRequests");
        source.ShouldContain("StatusCodes.Status503ServiceUnavailable");
        source.ShouldContain("AbuseReasonCodes.AccountUnlockVerifyAttemptsExceeded");
        source.ShouldContain("AbuseReasonCodes.CounterStoreUnavailable");
    }

    [Fact]
    public void Account_unlock_sql_only_starts_for_currently_locked_accounts_and_clears_lockout_on_verify()
    {
        string sql = File.ReadAllText(ProjectFile("Rigging", "Database", "Baseline", "000_treehammock_canonical_database.sql"));

        sql.ShouldContain("create or replace function lookup_locked_recovery_account");
        sql.ShouldContain("create or replace function start_unlock_account");
        sql.ShouldContain("create or replace function cancel_unlock_account");
        sql.ShouldContain("create or replace function verify_unlock_account");
        sql.ShouldContain("unlock_when is not null");
        sql.ShouldContain("unlock_when > p_now");
        sql.ShouldContain("phone_number text");
        sql.ShouldContain("phone_country_code text");
        sql.ShouldContain("t.method = 2");
        sql.ShouldContain("t.verified = true");
        sql.ShouldContain("lockout_security_stamp uuid not null");
        sql.ShouldContain("lockout_unlock_when timestamp with time zone not null");
        sql.ShouldContain("p_accountSecurityStamp uuid");
        sql.ShouldContain("p_lockoutUnlockWhen timestamp with time zone");
        sql.ShouldContain("v_security_stamp is distinct from p_accountSecurityStamp");
        sql.ShouldContain("v_unlock_when is distinct from p_lockoutUnlockWhen");
        sql.ShouldContain("v_account_security_stamp is distinct from v_recovery.lockout_security_stamp");
        sql.ShouldContain("v_account_unlock_when is distinct from v_recovery.lockout_unlock_when");
        sql.ShouldContain("set status = 14");
        sql.ShouldContain("set unlock_when = null,");
        sql.ShouldContain("login_failures = 0");
        sql.ShouldContain("if v_recovery.status = 7 then");
        sql.ShouldContain("if v_recovery.status = 4 then");
        sql.ShouldContain("p_expiration timestamp with time zone");
        sql.ShouldContain("p_method smallint");
        sql.ShouldContain("if p_method not in (1, 2) then");
        sql.ShouldContain("return query select 10::smallint");
        sql.ShouldContain("p_method,");
        sql.ShouldContain("method = excluded.method");
        sql.ShouldNotContain("create or replace function start_recover_account");
        sql.ShouldNotContain("p_createdOn + interval '1 day'");
    }


    [Fact]
    public void Account_unlock_start_request_accepts_identifier_and_delivery_method_and_stale_recovery_enums_are_removed()
    {
        string model = File.ReadAllText(ProjectFile("Models", "Recovery", "AccountRecovery.cs"));

        model.ShouldContain("public AccountRecoveryRequest(string identifier)");
        model.ShouldContain("public AccountRecoveryRequest(string identifier, AccountUnlockDeliveryMethod deliveryMethod)");
        model.ShouldContain("public required string identifier { get; set; }");
        model.ShouldContain("public AccountUnlockDeliveryMethod deliveryMethod { get; set; } = AccountUnlockDeliveryMethod.EMAIL;");
        model.ShouldNotContain("currentTime");
        model.ShouldNotContain("LocalDateTime");
        File.Exists(ProjectFile("RiggingSupport", "Enum", "AccountRecovery.cs")).ShouldBeFalse();
        File.Exists(ProjectFile("Entities", "AccountRecovery.cs")).ShouldBeFalse();
    }

    [Fact]
    public void Account_unlock_delivery_uses_templated_email_and_sms_sender_contracts()
    {
        string service = File.ReadAllText(ProjectFile("Services", "AccountRecoveryService.cs"));
        string smtp = File.ReadAllText(ProjectFile("Services", "SMTPService.cs"));
        string subjects = File.ReadAllText(ProjectFile("Rigging", "Config", "EmailSubjectSettings.cs"));
        string templates = File.ReadAllText(ProjectFile("Rigging", "Config", "EmailTemplateSettings.cs"));

        service.ShouldContain("TryDeliverUnlockToken");
        service.ShouldContain("AccountUnlockDeliveryMethod.EMAIL");
        service.ShouldContain("AccountUnlockDeliveryMethod.SMS");
        service.ShouldContain("_smtpService.AccountUnlockLetter");
        service.ShouldContain("_smsSender.SendCode");
        service.ShouldContain("request.deliveryMethod,");
        service.ShouldNotContain("BuildUnlockEmailBody");
        smtp.ShouldContain("AccountUnlockLetter");
        subjects.ShouldContain("AccountUnlock");
        templates.ShouldContain("AccountUnlock");
        File.Exists(ProjectFile("email_templates", "AccountUnlock.html")).ShouldBeTrue();
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
