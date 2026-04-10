using Npgsql;

namespace AuthService.Infrastructure.Persistence;

/// <summary>
/// Sets the PostgreSQL session variable <c>app.current_tenant_id</c> so that
/// Row-Level Security policies can enforce tenant isolation.
/// <c>SET LOCAL</c> is transaction-scoped, so the command must run within an
/// explicit transaction — hence the required <paramref name="tx"/> parameter.
/// </summary>
internal static class TenantContextHelper
{
    internal static async Task SetTenantContextAsync(
        NpgsqlConnection conn,
        NpgsqlTransaction tx,
        Guid tenantId,
        CancellationToken ct)
    {
        // tenantId is a Guid so ToString() is injection-safe (always UUID format).
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = $"SET LOCAL app.current_tenant_id = '{tenantId}'";
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
