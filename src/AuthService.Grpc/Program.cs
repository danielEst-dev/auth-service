using AuthService.Infrastructure;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Config: appsettings.json → appsettings.{env}.json → appsettings.Local.json
    builder.Configuration
        .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
        .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
        .AddJsonFile("appsettings.Local.json", optional: true, reloadOnChange: true)
        .AddEnvironmentVariables();

    // Serilog
    builder.Host.UseSerilog((ctx, services, config) =>
        config.ReadFrom.Configuration(ctx.Configuration)
              .ReadFrom.Services(services)
              .Enrich.FromLogContext()
              .WriteTo.Console());

    // gRPC
    builder.Services.AddGrpc(options =>
    {
        options.EnableDetailedErrors = builder.Environment.IsDevelopment();
    });

    // Infrastructure (Postgres, Redis)
    builder.Services.AddInfrastructure(builder.Configuration);

    // OpenTelemetry
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService("auth-service"))
        .WithTracing(t => t
            .AddAspNetCoreInstrumentation())
        .WithMetrics(m => m
            .AddAspNetCoreInstrumentation()
            .AddPrometheusExporter());

    var app = builder.Build();

    // Run DbUp migrations on startup
    app.Services.RunMigrations();

    app.UseSerilogRequestLogging();

    // Prometheus scrape endpoint
    app.MapPrometheusScrapingEndpoint("/metrics");

    app.MapGet("/healthz", () => Results.Ok(new { status = "healthy" }));

    app.Run();
}
catch (Exception ex) when (ex is not HostAbortedException)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
