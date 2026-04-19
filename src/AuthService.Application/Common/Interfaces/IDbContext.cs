namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// The unit-of-work boundary for a single logical operation. One scoped instance per
/// request — handlers open a transaction, repositories enlist automatically, and the
/// outbox write commits atomically with the business state.
///
/// In production this is driven by <c>UnitOfWorkInterceptor</c> (gRPC) and
/// <c>UnitOfWorkActionFilter</c> (MVC) — handlers and controllers don't call these
/// methods directly. Expose them here for direct use in background services or tests.
/// </summary>
public interface IDbContext
{
    bool HasActiveTransaction { get; }

    /// <summary>
    /// Opens a connection, starts a transaction, and (if <paramref name="tenantId"/> is
    /// non-null) sets <c>app.current_tenant_id</c> so RLS policies apply.
    /// </summary>
    Task BeginAsync(Guid? tenantId = null, CancellationToken ct = default);

    Task CommitAsync(CancellationToken ct = default);
    Task RollbackAsync(CancellationToken ct = default);
}
