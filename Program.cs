using System.IO.Compression;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.ResponseCompression;

using Newtonsoft.Json;

using treehammock.Rigging.Database;
using treehammock.Services;
using treehammock.Rigging.Cache;
using treehammock.Repos;
using treehammock.Rigging.Config;
using NodaTime.Serialization.JsonNet;
using NodaTime;
using treehammock.Rigging.Sidewalk;
using treehammock.Rigging.Provider;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.DependencyInjection;
using treehammock.Rigging.Hosting;
using treehammock.Models.Api;


var builder = WebApplication.CreateBuilder(args);
{
    var services = builder.Services;
    var env = builder.Environment;

    // HTTP/S 3 : br - brotli
    services.AddResponseCompression(options =>
    {
        options.EnableForHttps = true;
        options.Providers.Add<BrotliCompressionProvider>();
    });

    services.Configure<BrotliCompressionProviderOptions>(options =>
    {
        options.Level = CompressionLevel.Fastest;
    });

    services.AddRequestDecompression();

    services.AddControllers()
        .ConfigureApiBehaviorOptions(options =>
        {
            options.InvalidModelStateResponseFactory = context => ApiResponses.InvalidModelState(context.ModelState);
        })
        .AddApplicationPart(typeof(treehammock.Controllers.AccountLoginController).Assembly)
        .AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
        })
        .AddNewtonsoftJson(options =>
    {
        options.SerializerSettings.Converters.Add(new Newtonsoft.Json.Converters.StringEnumConverter());
        options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
        options.SerializerSettings.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb);
    });

    services.AddTreehammockServices(builder.Configuration);

}

builder.Services.AddHttpClient();

// Configure HTTP request pipeline
builder.WebHost.ConfigureKestrel((context, options) =>
{
    var hostingSettings = context.Configuration
        .GetRequiredSection("HostingSettings")
        .Get<HostingSettings>() ?? new HostingSettings();

    HostingConfigurator.ConfigureKestrel(options, hostingSettings);
});

var app = builder.Build();

var hostingSettings = app.Configuration
    .GetRequiredSection("HostingSettings")
    .Get<HostingSettings>() ?? new HostingSettings();

if (hostingSettings.UseForwardedHeaders)
{
    app.UseForwardedHeaders(HostingConfigurator.CreateForwardedHeadersOptions(hostingSettings));
}

if (hostingSettings.UseHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseResponseCompression();

app.UseRequestDecompression();

app.UseMiddleware<JsonWebTokenMiddleware>();

app.MapControllers();

app.Run();
public partial class Program { }
