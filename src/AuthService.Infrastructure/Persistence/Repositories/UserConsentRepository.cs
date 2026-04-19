using System.Text.Json;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;
using NpgsqlTypes;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class UserConsentRepository(IDbSessionProvider sessions) : IUserConsentRepository
{
    private const string SelectColumns = """
        id, tenant_id, user_id, client_id, scopes, granted_at, expires_at
        """;

    public async Task<UserConsent?> GetAsync(Guid tenantId, Guid userId, Guid clientDbId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM user_consents
            WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(userId);
        cmd.Parameters.AddWithValue(clientDbId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapConsent(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task CreateAsync(UserConsent consent, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(consent.TenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO user_consents (id, tenant_id, user_id, client_id, scopes, granted_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (tenant_id, user_id, client_id)
            DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = EXCLUDED.granted_at, expires_at = EXCLUDED.expires_at
            """;

        cmd.Parameters.AddWithValue(consent.Id);
        cmd.Parameters.AddWithValue(consent.TenantId);
        cmd.Parameters.AddWithValue(consent.UserId);
        cmd.Parameters.AddWithValue(consent.ClientDbId);
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(consent.Scopes) });
        cmd.Parameters.AddWithValue(consent.GrantedAt);
        cmd.Parameters.AddWithValue(consent.ExpiresAt ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task UpdateAsync(UserConsent consent, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(consent.TenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            UPDATE user_consents
            SET scopes = $3, granted_at = $4, expires_at = $5
            WHERE id = $1 AND tenant_id = $2
            """;

        cmd.Parameters.AddWithValue(consent.Id);
        cmd.Parameters.AddWithValue(consent.TenantId);
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(consent.Scopes) });
        cmd.Parameters.AddWithValue(consent.GrantedAt);
        cmd.Parameters.AddWithValue(consent.ExpiresAt ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    private static UserConsent MapConsent(NpgsqlDataReader r) =>
        UserConsent.Reconstitute(
            id: r.GetGuid(0),
            tenantId: r.GetGuid(1),
            userId: r.GetGuid(2),
            clientDbId: r.GetGuid(3),
            scopes: JsonSerializer.Deserialize<List<string>>(r.GetString(4))?.AsReadOnly()
                    ?? (IReadOnlyList<string>)[],
            grantedAt: r.GetFieldValue<DateTimeOffset>(5),
            expiresAt: r.IsDBNull(6) ? null : r.GetFieldValue<DateTimeOffset>(6)
        );
}
