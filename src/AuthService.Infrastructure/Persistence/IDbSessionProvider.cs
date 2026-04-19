namespace AuthService.Infrastructure.Persistence;

/// <summary>
/// Every repository receives its connection + transaction through this provider. It hides
/// whether work is enlisted in the ambient <c>IUnitOfWork</c> or running as a standalone
/// short-lived transaction — repos stay ignorant of transaction scope.
/// </summary>
public interface IDbSessionProvider
{
    /// <summary>
    /// Returns an ambient session when a UoW transaction is active, otherwise opens a
    /// fresh owning session (new connection + new transaction + tenant context).
    /// </summary>
    Task<DbSession> GetSessionAsync(Guid? tenantId = null, CancellationToken ct = default);
}
