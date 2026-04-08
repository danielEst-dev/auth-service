using AuthService.Application.Common.Interfaces;
using AuthService.Infrastructure.Cache;
using AuthService.Infrastructure.Persistence;
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

        // Redis
        var redisConnStr = configuration.GetConnectionString("Redis")
            ?? throw new InvalidOperationException("Missing connection string: Redis");

        services.AddSingleton<IConnectionMultiplexer>(
            _ => ConnectionMultiplexer.Connect(redisConnStr));

        services.AddSingleton<ICacheService, RedisCacheService>();

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
