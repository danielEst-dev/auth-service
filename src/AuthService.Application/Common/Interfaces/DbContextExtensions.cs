namespace AuthService.Application.Common.Interfaces;

public static class DbContextExtensions
{
    /// <summary>
    /// Runs <paramref name="work"/> inside a unit-of-work transaction. Commits on success,
    /// rolls back on any exception (including cancellation), then rethrows.
    /// </summary>
    public static async Task<T> ExecuteAsync<T>(
        this IDbContext dbContext,
        Guid? tenantId,
        Func<Task<T>> work,
        CancellationToken ct = default)
    {
        await dbContext.BeginAsync(tenantId, ct);
        try
        {
            var result = await work();
            await dbContext.CommitAsync(ct);
            return result;
        }
        catch
        {
            await dbContext.RollbackAsync(ct);
            throw;
        }
    }

    /// <summary>Void overload.</summary>
    public static async Task ExecuteAsync(
        this IDbContext dbContext,
        Guid? tenantId,
        Func<Task> work,
        CancellationToken ct = default)
    {
        await dbContext.BeginAsync(tenantId, ct);
        try
        {
            await work();
            await dbContext.CommitAsync(ct);
        }
        catch
        {
            await dbContext.RollbackAsync(ct);
            throw;
        }
    }
}
