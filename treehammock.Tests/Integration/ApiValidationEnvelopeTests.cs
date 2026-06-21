using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Shouldly;

using treehammock.Models.Api;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public class ApiValidationEnvelopeTests
{
    [Fact]
    public async Task Missing_body_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            new StringContent(string.Empty, Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrors(document);
    }

    [Fact]
    public async Task Malformed_json_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            new StringContent("{", Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrors(document);
    }

    [Fact]
    public async Task Invalid_model_data_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "not-an-email",
              "password": "ValidPassword1!",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "emailAddress");
    }

    [Fact]
    public async Task None_two_factor_configuration_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/twofactor/select",
            JsonContent("""
            {
              "configuration": "NONE"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "configuration");
    }


    [Fact]
    public async Task Negative_two_factor_destination_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/twofactor/select",
            JsonContent("""
            {
              "configuration": "EMAIL",
              "destination": -1
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "destination");
    }

    [Fact]
    public async Task Empty_two_factor_code_key_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "SMS_KEY",
              "codeKey": ""
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "codeKey");
    }

    [Fact]
    public async Task Runtime_config_validation_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "password": "short"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "password");
    }

    [Fact]
    public async Task Runtime_login_validation_rejects_supplied_short_username()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "username": "ab",
              "password": "ValidPassword1!"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "username");
    }

    [Fact]
    public async Task Runtime_login_validation_rejects_supplied_invalid_email_even_with_valid_username()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "emailAddress": "not-an-email",
              "username": "reader",
              "password": "ValidPassword1!"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "emailAddress");
    }

    [Fact]
    public async Task Runtime_setup_validation_rejects_supplied_short_username()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "username": "ab",
              "password": "ValidPassword1!",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "username");
    }

    [Fact]
    public async Task Runtime_setup_validation_rejects_country_none()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "password": "ValidPassword1!",
              "country": "NONE"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "country");
    }

    [Fact]
    public async Task Runtime_setup_validation_returns_standard_validation_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "password": "short",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "password");
    }

    [Fact]
    public async Task Custom_anonymous_requestaccess_reaches_model_validation_without_active_token()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/requestaccess",
            JsonContent("""
            {
              "password": "ValidPassword1!"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrors(document);
    }

    [Fact]
    public async Task Custom_anonymous_setupaccount_reaches_model_validation_without_active_token()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "not-an-email",
              "password": "ValidPassword1!",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        AssertHasValidationErrorFor(document, "emailAddress");
    }

    [Fact]
    public async Task Unauthorized_protected_endpoint_returns_standard_auth_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.GetAsync("/account/view");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString());
        document.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
    }

    [Fact]
    public async Task Unauthenticated_protected_placeholder_with_missing_body_returns_auth_envelope()
    {
        using var factory = new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings());
        using var client = CreateHttpsClient(factory);

        using var response = await client.PostAsync(
            "/account/logoff",
            new StringContent(string.Empty, Encoding.UTF8, "application/json"));

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_FAILED.ToString());
        document.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.AUTHENTICATION_FAILED.ToString());
    }

    private static HttpClient CreateHttpsClient(TreehammockWebApplicationFactory factory)
    {
        return factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
    }

    private static StringContent JsonContent(string json)
    {
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    private static async Task<JsonDocument> ReadJson(HttpResponseMessage response)
    {
        string json = await response.Content.ReadAsStringAsync();
        json.ShouldNotBeNullOrWhiteSpace();
        return JsonDocument.Parse(json);
    }

    private static void AssertFailureEnvelope(JsonDocument document, int statusCode, string code)
    {
        JsonElement root = document.RootElement;
        if (root.TryGetProperty("success", out JsonElement success))
        {
            success.GetBoolean().ShouldBeFalse();
            root.GetProperty("statusCode").GetInt32().ShouldBe(statusCode);
            root.GetProperty("code").GetString().ShouldBe(code);
            return;
        }

        root.GetProperty("status").GetInt32().ShouldBe(statusCode);
    }

    private static void AssertHasValidationErrors(JsonDocument document)
    {
        JsonElement errors = document.RootElement.GetProperty("errors");
        (errors.ValueKind == JsonValueKind.Array || errors.ValueKind == JsonValueKind.Object).ShouldBeTrue();
        if (errors.ValueKind == JsonValueKind.Array)
        {
            errors.GetArrayLength().ShouldBeGreaterThan(0);
        }
        else
        {
            errors.EnumerateObject().Any().ShouldBeTrue();
        }
    }

    private static void AssertHasValidationErrorFor(JsonDocument document, string field)
    {
        JsonElement errors = document.RootElement.GetProperty("errors");
        if (errors.ValueKind == JsonValueKind.Array)
        {
            errors.EnumerateArray().Any(error =>
            {
                if (!error.TryGetProperty("field", out JsonElement fieldElement))
                {
                    return false;
                }

                return string.Equals(fieldElement.GetString(), field, StringComparison.OrdinalIgnoreCase);
            }).ShouldBeTrue($"Expected validation error for field '{field}'.");
            return;
        }

        errors.EnumerateObject().Any(error => string.Equals(error.Name, field, StringComparison.OrdinalIgnoreCase))
            .ShouldBeTrue($"Expected validation error for field '{field}'.");
    }
}
