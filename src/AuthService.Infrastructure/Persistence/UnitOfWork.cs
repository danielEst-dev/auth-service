using AuthService.Application.Common.Interfaces;
using Npgsql;

namespace AuthService.Infrastructure.Persistence;

/// <summary>
/// Scoped unit-of-work. Implements both the Application-facing <see cref="IDbContext"/>
/// and the Infrastructure-internal <see cref="IDbSessionProvider"/> — repos transparently
/// enlist in the active transaction when one exists.
/// </summary>
public sealed class UnitOfWork(NpgsqlDataSource dataSource)
    : IDbContext, IDbSessionProvider, IAsyncDisposable
{
    private NpgsqlConnection? _conn;
    private NpgsqlTransaction? _tx;

    public bool HasActiveTransaction => _tx is not null;

    // ── IDbContext ────────────────────────────────────────────────────────────

    public async Task BeginAsync(Guid? tenantId = null, CancellationToken ct = default)
    {
        if (_tx is not null)
            throw new InvalidOperationException("A transaction is already active on this unit of work.");

        _conn = await dataSource.OpenConnectionAsync(ct);
        _tx   = await _conn.BeginTransactionAsync(ct);

        if (tenantId.HasValue)
            await SetTenantContextAsync(_conn, _tx, tenantId.Value, ct);
    }

    public async Task CommitAsync(CancellationToken ct = default)
    {
        if (_tx is null)
            throw new InvalidOperationException("No active transaction to commit.");

        await _tx.CommitAsync(ct);
        await DisposeTxAsync();
    }

    public async Task RollbackAsync(CancellationToken ct = default)
    {
        if (_tx is null) return;
        try { await _tx.RollbackAsync(ct); }
        catch { /* swallow — the connection may already be broken */ }
        await DisposeTxAsync();
    }

    // ── IDbSessionProvider ────────────────────────────────────────────────────

    public async Task<DbSession> GetSessionAsync(Guid? tenantId = null, CancellationToken ct = default)
    {
        if (_tx is not null)
        {
            // Ambient branch. If the caller knows a tenant (e.g. AcceptInvitation creating
            // a user inside a tenant-free RPC), re-run SET LOCAL on the ambient transaction.
            // SET LOCAL is tx-scoped so this is cheap and correct — later repo calls in the
            // same UoW inherit the last value set.
            if (tenantId.HasValue)
                await SetTenantContextAsync(_conn!, _tx, tenantId.Value, ct);
            return DbSession.Ambient(_conn!, _tx);
        }

        // No ambient UoW — open a fresh owning session for this single call.
        var conn = await dataSource.OpenConnectionAsync(ct);
        var tx   = await conn.BeginTransactionAsync(ct);
        if (tenantId.HasValue)
            await SetTenantContextAsync(conn, tx, tenantId.Value, ct);
        return DbSession.Owning(conn, tx);
    }

    // ── IAsyncDisposable ──────────────────────────────────────────────────────

    public async ValueTask DisposeAsync()
    {
        if (_tx is not null)
            await RollbackAsync();
    }

    // ── Private ───────────────────────────────────────────────────────────────

    private async Task DisposeTxAsync()
    {
        if (_tx   is not null) { await _tx.DisposeAsync();   _tx   = null; }
        if (_conn is not null) { await _conn.DisposeAsync(); _conn = null; }
    }

    private static async Task SetTenantContextAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, Guid tenantId, CancellationToken ct)
    {
        // tenantId is a Guid — ToString() always produces a safe UUID literal.
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = $"SET LOCAL app.current_tenant_id = '{tenantId}'";
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
