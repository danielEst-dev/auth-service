using Npgsql;

namespace AuthService.Infrastructure.Persistence;

/// <summary>
/// A short-lived Postgres work unit handed to repositories. Either ambient (shares the
/// enclosing <see cref="UnitOfWork"/>'s connection/transaction — the repo does NOT commit)
/// or standalone (the repo committed it on its own — the session commits/rolls back itself
/// on dispose).
/// </summary>
public sealed class DbSession : IAsyncDisposable
{
    public NpgsqlConnection Connection { get; }
    public NpgsqlTransaction Transaction { get; }

    /// <summary>
    /// True when the session owns its connection/transaction. Ambient (UoW-bound) sessions
    /// set this false — <see cref="CommitAsync"/> and <see cref="DisposeAsync"/> are no-ops
    /// because the enclosing unit-of-work controls those lifecycles.
    /// </summary>
    private readonly bool _owning;
    private bool _committed;

    private DbSession(NpgsqlConnection conn, NpgsqlTransaction tx, bool owning)
    {
        Connection = conn;
        Transaction = tx;
        _owning = owning;
    }

    internal static DbSession Owning(NpgsqlConnection conn, NpgsqlTransaction tx) =>
        new(conn, tx, owning: true);

    internal static DbSession Ambient(NpgsqlConnection conn, NpgsqlTransaction tx) =>
        new(conn, tx, owning: false);

    public async Task CommitAsync(CancellationToken ct = default)
    {
        if (!_owning || _committed) return;
        await Transaction.CommitAsync(ct);
        _committed = true;
    }

    public async ValueTask DisposeAsync()
    {
        if (!_owning) return;
        try
        {
            if (!_committed)
                await Transaction.RollbackAsync();
        }
        catch { /* connection may be broken; swallow */ }
        await Transaction.DisposeAsync();
        await Connection.DisposeAsync();
    }
}
