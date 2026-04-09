using AuthService.Application.Common.Interfaces;
using AuthService.Infrastructure.Cache;
using AuthService.Infrastructure.Messaging;
using AuthService.Infrastructure.Persistence;
using AuthService.Infrastructure.Persistence.Repositories;
using AuthService.Infrastructure.Security;
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

        // Repositories
        services.AddScoped<ITenantRepository, TenantRepository>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();

        // Redis
        var redisConnStr = configuration.GetConnectionString("Redis")
            ?? throw new InvalidOperationException("Missing connection string: Redis");

        services.AddSingleton<IConnectionMultiplexer>(
            _ => ConnectionMultiplexer.Connect(redisConnStr));

        services.AddSingleton<ICacheService, RedisCacheService>();

        // Security
        services.AddSingleton<IPasswordHasher, PasswordHasher>();
        services.AddSingleton<ITokenService, JwtTokenService>();

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

        services.AddScoped<IEventPublisher, MassTransitEventPublisher>();
        services.AddScoped<DomainEventDispatcher>();

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
