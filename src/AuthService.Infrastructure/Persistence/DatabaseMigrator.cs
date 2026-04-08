using DbUp;
using DbUp.Engine.Output;
using Microsoft.Extensions.Logging;

namespace AuthService.Infrastructure.Persistence;

public static class DatabaseMigrator
{
    public static void MigrateDatabase(string connectionString, ILogger logger)
    {
        EnsureDatabase.For.PostgresqlDatabase(connectionString);

        var upgrader = DeployChanges.To
            .PostgresqlDatabase(connectionString)
            .WithScriptsEmbeddedInAssembly(typeof(DatabaseMigrator).Assembly)
            .WithTransactionPerScript()
            .LogTo(new MicrosoftExtensionsUpgradeLog(logger))
            .Build();

        if (!upgrader.IsUpgradeRequired())
        {
            logger.LogInformation("Database is up to date. No migrations to apply.");
            return;
        }

        var result = upgrader.PerformUpgrade();

        if (!result.Successful)
        {
            logger.LogError(result.Error, "Database migration failed");
            throw new Exception("Database migration failed", result.Error);
        }

        logger.LogInformation("Database migration completed successfully");
    }

    private sealed class MicrosoftExtensionsUpgradeLog(ILogger logger) : IUpgradeLog
    {
        public void LogTrace(string format, params object[] args) =>
            logger.LogTrace(format, args);

        public void LogDebug(string format, params object[] args) =>
            logger.LogDebug(format, args);

        public void LogInformation(string format, params object[] args) =>
            logger.LogInformation(format, args);

        public void LogWarning(string format, params object[] args) =>
            logger.LogWarning(format, args);

        public void LogError(string format, params object[] args) =>
            logger.LogError(format, args);

        public void LogError(Exception ex, string format, params object[] args) =>
            logger.LogError(ex, format, args);
    }
}
