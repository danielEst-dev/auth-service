using AuthService.Application.Common.Interfaces;
using AuthService.Infrastructure.Cache;
using AuthService.Infrastructure.Messaging;
using AuthService.Infrastructure.Persistence;
using AuthService.Infrastructure.Persistence.Repositories;
using AuthService.Infrastructure.Security;
// ReSharper disable once RedundantUsingDirective — IDbSessionProvider lives here
using MassTransit;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;


namespace AuthService.Infrastructure;

public static class InfrastructureServiceExtensions
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // PostgreSQL
        var pgConnStr = configuration.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("Missing connection string: Postgres");

        services.AddNpgsqlDataSource(pgConnStr);

        // Unit of work — scoped, one per request. Implements both IDbContext (for
        // handlers/adapters to control the transaction boundary) and IDbSessionProvider
        // (for repositories and the outbox writer to transparently enlist).
        services.AddScoped<UnitOfWork>();
        services.AddScoped<IDbContext>(sp => sp.GetRequiredService<UnitOfWork>());
        services.AddScoped<IDbSessionProvider>(sp => sp.GetRequiredService<UnitOfWork>());

        // Repositories
        services.AddScoped<ITenantRepository, TenantRepository>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
        services.AddScoped<IRoleRepository, RoleRepository>();
        services.AddScoped<IMfaRepository, MfaRepository>();
        services.AddScoped<IVerificationTokenRepository, VerificationTokenRepository>();
        services.AddScoped<ITenantInvitationRepository, TenantInvitationRepository>();

        // Redis
        var redisConnStr = configuration.GetConnectionString("Redis")
            ?? throw new InvalidOperationException("Missing connection string: Redis");

        services.AddSingleton<IConnectionMultiplexer>(
            _ => ConnectionMultiplexer.Connect(redisConnStr));

        services.AddSingleton<ICacheService, RedisCacheService>();
        services.AddScoped<IPermissionCacheService, PermissionCacheService>();

        // Security
        services.AddSingleton<IPasswordHasher, PasswordHasher>();
        services.AddSingleton<ITokenService, JwtTokenService>();
        services.AddSingleton<ITotpService, TotpService>();
        services.AddSingleton<IDataProtector, AesDataProtector>();
        services.AddScoped<IMfaVerificationService, MfaVerificationService>();
        services.AddSingleton<IRateLimiter, RedisRateLimiter>();

        // OAuth / OIDC repositories
        services.AddScoped<IOAuthClientRepository, OAuthClientRepository>();
        services.AddScoped<IAuthorizationCodeRepository, AuthorizationCodeRepository>();
        services.AddScoped<IUserConsentRepository, UserConsentRepository>();
        services.AddScoped<ISigningKeyRepository, SigningKeyRepository>();

        // Signing key pipeline: shared data protector + JWKS builder + orchestrator
        services.AddSingleton<IJwksBuilder, JwksBuilder>();
        services.AddSingleton<SigningKeyService>();
        services.AddSingleton<ISigningKeyService>(sp => sp.GetRequiredService<SigningKeyService>());
        services.AddHostedService(sp => sp.GetRequiredService<SigningKeyService>());

        // RabbitMQ / MassTransit
        var rabbitSection = configuration.GetSection("RabbitMQ");
        services.AddMassTransit(bus =>
        {
            bus.UsingRabbitMq((ctx, cfg) =>
            {
                cfg.Host(rabbitSection["Host"] ?? "localhost", rabbitSection["VirtualHost"] ?? "/", h =>
                {
                    h.Username(rabbitSection["Username"] ?? "guest");
                    h.Password(rabbitSection["Password"] ?? "guest");
                });

                cfg.ConfigureEndpoints(ctx);
            });
        });

        // Outbox pipeline: events are durably queued to `outbox_events`, then the
        // OutboxRelay background service publishes them to MassTransit/RabbitMQ.
        services.AddScoped<IOutboxWriter, OutboxWriter>();
        services.AddScoped<IEventPublisher, MassTransitEventPublisher>();
        services.AddScoped<IDomainEventDispatcher, DomainEventDispatcher>();
        services.AddHostedService<OutboxRelay>();

        return services;
    }

    public static void RunMigrations(this IServiceProvider services)
    {
        var configuration = services.GetRequiredService<IConfiguration>();
        var loggerFactory = services.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger("DatabaseMigrator");

        var connStr = configuration.GetConnectionString("Postgres")
            ?? throw new InvalidOperationException("Missing connection string: Postgres");

        DatabaseMigrator.MigrateDatabase(connStr, logger);
    }
}
