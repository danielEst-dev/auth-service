using AuthService.Application;
using AuthService.Grpc.Filters;
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

    // MVC controllers (OIDC HTTP endpoints: /oauth/authorize, /oauth/token, etc.)
    // The UoW filter wraps every action in a per-request transaction.
    builder.Services.AddControllers(options =>
    {
        options.Filters.Add<UnitOfWorkActionFilter>();
    });

    // gRPC + interceptors on every RPC.
    // Order matters:
    //   1. TenantResolution — sets UserState["TenantId"] for downstream interceptors
    //   2. ExceptionTranslation — catches Application exceptions AFTER the UoW has
    //      already rolled back, translating them into gRPC statuses
    //   3. UnitOfWork — begins tx seeded with the tenant, commits/rolls back
    //   4. Permission — reads under the UoW tx
    //   5. handler
    builder.Services.AddGrpc(options =>
    {
        options.EnableDetailedErrors = builder.Environment.IsDevelopment();
        options.Interceptors.Add<TenantResolutionInterceptor>();
        options.Interceptors.Add<ExceptionTranslationInterceptor>();
        options.Interceptors.Add<UnitOfWorkInterceptor>();
        options.Interceptors.Add<PermissionInterceptor>();
    });

    // gRPC reflection — enables grpcurl / Postman service discovery
    builder.Services.AddGrpcReflection();

    // Application (validators, command handlers)
    builder.Services.AddApplication();

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

    // MVC controllers (OIDC HTTP endpoints)
    app.MapControllers();

    // gRPC services
    app.MapGrpcService<AuthServiceImpl>();
    app.MapGrpcService<TenantServiceImpl>();
    app.MapGrpcService<RoleServiceImpl>();
    app.MapGrpcService<MfaServiceImpl>();
    app.MapGrpcService<VerificationServiceImpl>();

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
