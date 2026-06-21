using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

using treehammock.Rigging.Authorization.Attributes;
using treehammock.Rigging.Config;
using treehammock.Services.SystemTesting;

namespace treehammock.Controllers;

[AllowAnonymous]
[ApiController]
[Route("__system-test/deliveries")]
[Produces("application/json")]
public sealed class SystemTestDeliveryController : ControllerBase
{
    public const string TestKeyHeaderName = "X-System-Test-Key";

    private readonly ISystemTestDeliveryCapture _capture;
    private readonly SystemTestSettings _settings;

    public SystemTestDeliveryController(
        ISystemTestDeliveryCapture capture,
        IOptions<SystemTestSettings> settings)
    {
        _capture = capture;
        _settings = settings.Value;
    }

    [HttpGet("latest")]
    public async Task<IActionResult> Latest([FromQuery] string channel, [FromQuery] string purpose, [FromQuery] string destination)
    {
        IActionResult? guard = GuardAccess();
        if (guard is not null)
        {
            return guard;
        }

        if (string.IsNullOrWhiteSpace(channel) || string.IsNullOrWhiteSpace(purpose) || string.IsNullOrWhiteSpace(destination))
        {
            return BadRequest(new { success = false, code = "SYSTEM_TEST_DELIVERY_QUERY_INVALID" });
        }

        SystemTestDeliveryRecord? record = await _capture.GetLatest(channel.Trim(), purpose.Trim(), destination.Trim());
        if (record is null)
        {
            return NotFound(new { success = false, code = "SYSTEM_TEST_DELIVERY_NOT_FOUND" });
        }

        return Ok(new { success = true, code = "SYSTEM_TEST_DELIVERY_FOUND", data = record });
    }

    [HttpDelete]
    public async Task<IActionResult> Clear()
    {
        IActionResult? guard = GuardAccess();
        if (guard is not null)
        {
            return guard;
        }

        int cleared = await _capture.Clear();
        return Ok(new { success = true, code = "SYSTEM_TEST_DELIVERIES_CLEARED", data = new { cleared } });
    }

    private IActionResult? GuardAccess()
    {
        if (!_settings.Enabled || !_settings.EnableTestInspectionEndpoints)
        {
            return NotFound();
        }

        if (string.IsNullOrWhiteSpace(_settings.TestKey))
        {
            return NotFound();
        }

        string? supplied = Request.Headers[TestKeyHeaderName].FirstOrDefault();
        return string.Equals(supplied, _settings.TestKey, StringComparison.Ordinal)
            ? null
            : Unauthorized(new { success = false, code = "SYSTEM_TEST_KEY_INVALID" });
    }
}
