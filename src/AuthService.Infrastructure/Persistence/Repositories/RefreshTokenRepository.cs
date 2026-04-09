using System.Net;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;
using NpgsqlTypes;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class RefreshTokenRepository(NpgsqlDataSource dataSource) : IRefreshTokenRepository
{
    private const string SelectColumns = """
        id, tenant_id, user_id, token_hash, jti,
        device_info, ip_address,
        issued_at, expires_at, revoked_at, replaced_by_id
        """;

    public async Task<RefreshToken?> GetByTokenHashAsync(Guid tenantId, string tokenHash, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await SetTenantContext(conn, tenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM refresh_tokens
            WHERE tenant_id = $1 AND token_hash = $2
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(tokenHash);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? MapToken(reader) : null;
    }

    public async Task<Guid> CreateAsync(RefreshToken token, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await SetTenantContext(conn, token.TenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO refresh_tokens (
                id, tenant_id, user_id, token_hash, jti,
                device_info, ip_address,
                issued_at, expires_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7,
                $8, $9
            )
            RETURNING id
            """;

        cmd.Parameters.AddWithValue(token.Id);
        cmd.Parameters.AddWithValue(token.TenantId);
        cmd.Parameters.AddWithValue(token.UserId);
        cmd.Parameters.AddWithValue(token.TokenHash);
        cmd.Parameters.AddWithValue(token.Jti);
        cmd.Parameters.AddWithValue(token.DeviceInfo ?? (object)DBNull.Value);
        cmd.Parameters.Add(new NpgsqlParameter
        {
            NpgsqlDbType = NpgsqlDbType.Inet,
            Value = token.IpAddress is not null
                ? IPAddress.Parse(token.IpAddress)
                : DBNull.Value
        });
        cmd.Parameters.AddWithValue(token.IssuedAt);
        cmd.Parameters.AddWithValue(token.ExpiresAt);

        var result = await cmd.ExecuteScalarAsync(ct);
        return (Guid)result!;
    }

    public async Task UpdateAsync(RefreshToken token, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await SetTenantContext(conn, token.TenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE refresh_tokens SET
                revoked_at    = $2,
                replaced_by_id = $3
            WHERE id = $1 AND tenant_id = $4
            """;

        cmd.Parameters.AddWithValue(token.Id);
        cmd.Parameters.AddWithValue(token.RevokedAt ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(token.ReplacedById ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(token.TenantId);

        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RevokeAllForUserAsync(Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await SetTenantContext(conn, tenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(userId);

        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task SetTenantContext(NpgsqlConnection conn, Guid tenantId, CancellationToken ct)
    {
        // SET does not support parameterized values in PostgreSQL.
        // tenantId is a Guid (validated upstream), so ToString() is safe from injection.
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SET app.current_tenant_id = '{tenantId}'";
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static RefreshToken MapToken(NpgsqlDataReader r) =>
        RefreshToken.Reconstitute(
            id: r.GetGuid(0),
            tenantId: r.GetGuid(1),
            userId: r.GetGuid(2),
            tokenHash: r.GetString(3),
            jti: r.GetString(4),
            deviceInfo: r.IsDBNull(5) ? null : r.GetString(5),
            ipAddress: r.IsDBNull(6) ? null : r.GetFieldValue<IPAddress>(6).ToString(),
            issuedAt: r.GetFieldValue<DateTimeOffset>(7),
            expiresAt: r.GetFieldValue<DateTimeOffset>(8),
            revokedAt: r.IsDBNull(9) ? null : r.GetFieldValue<DateTimeOffset>(9),
            replacedById: r.IsDBNull(10) ? null : r.GetGuid(10)
        );
}
