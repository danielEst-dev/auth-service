using AuthService.Grpc.Interceptors;
using AuthService.Grpc.Services;
using AuthService.Infrastructure;
using Npgsql;
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

    // gRPC + TenantResolutionInterceptor on every RPC
    builder.Services.AddGrpc(options =>
    {
        options.EnableDetailedErrors = builder.Environment.IsDevelopment();
        options.Interceptors.Add<TenantResolutionInterceptor>();
    });

    // gRPC reflection — enables grpcurl / Postman service discovery
    builder.Services.AddGrpcReflection();

    // Infrastructure (Postgres, Redis, repositories, token service, password hasher)
    builder.Services.AddInfrastructure(builder.Configuration);

    // OpenTelemetry
    var otelEndpoint = builder.Configuration["OpenTelemetry:Endpoint"];
    builder.Services.AddOpenTelemetry()
        .ConfigureResource(r => r.AddService("auth-service"))
        .WithTracing(t =>
        {
            t.AddAspNetCoreInstrumentation()
             .AddNpgsql()
             .AddRedisInstrumentation();
            if (!string.IsNullOrWhiteSpace(otelEndpoint))
                t.AddOtlpExporter(o => o.Endpoint = new Uri(otelEndpoint));
        })
        .WithMetrics(m => m
            .AddAspNetCoreInstrumentation()
            .AddPrometheusExporter());

    builder.Services.AddHealthChecks();

    var app = builder.Build();

    // Run DbUp migrations on startup
    app.Services.RunMigrations();

    app.UseSerilogRequestLogging();

    // Prometheus scrape endpoint
    app.MapPrometheusScrapingEndpoint("/metrics");

    app.MapHealthChecks("/healthz");

    // gRPC services
    app.MapGrpcService<AuthServiceImpl>();
    app.MapGrpcService<TenantServiceImpl>();
    app.MapGrpcService<RoleServiceImpl>();

    // gRPC reflection (dev + staging only)
    if (!app.Environment.IsProduction())
        app.MapGrpcReflectionService();

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
