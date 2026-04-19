using System.Text.Json;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;
using NpgsqlTypes;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class OAuthClientRepository(IDbSessionProvider sessions) : IOAuthClientRepository
{
    private const string SelectColumns = """
        id, tenant_id, client_id, client_secret_hash, client_name, client_type,
        redirect_uris, post_logout_redirect_uris, allowed_scopes, allowed_grant_types,
        require_pkce, require_consent, access_token_lifetime, refresh_token_lifetime,
        is_active, created_at, updated_at
        """;

    // Cross-tenant lookup — RLS policy on oauth_clients allows empty tenant context
    public async Task<OAuthClient?> GetByClientIdAsync(string clientId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM oauth_clients
            WHERE client_id = $1 AND is_active = TRUE
            """;
        cmd.Parameters.AddWithValue(clientId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapClient(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task<OAuthClient?> GetByIdAsync(Guid tenantId, Guid id, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM oauth_clients
            WHERE id = $1 AND tenant_id = $2
            """;
        cmd.Parameters.AddWithValue(id);
        cmd.Parameters.AddWithValue(tenantId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapClient(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task CreateAsync(OAuthClient client, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(client.TenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO oauth_clients (
                id, tenant_id, client_id, client_secret_hash, client_name, client_type,
                redirect_uris, post_logout_redirect_uris, allowed_scopes, allowed_grant_types,
                require_pkce, require_consent, access_token_lifetime, refresh_token_lifetime,
                is_active, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10,
                $11, $12, $13, $14,
                $15, $16, $17
            )
            """;

        cmd.Parameters.AddWithValue(client.Id);
        cmd.Parameters.AddWithValue(client.TenantId);
        cmd.Parameters.AddWithValue(client.ClientId);
        cmd.Parameters.AddWithValue(client.ClientSecretHash ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(client.ClientName);
        cmd.Parameters.AddWithValue(client.ClientType);
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(client.RedirectUris) });
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(client.PostLogoutRedirectUris) });
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(client.AllowedScopes) });
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(client.AllowedGrantTypes) });
        cmd.Parameters.AddWithValue(client.RequirePkce);
        cmd.Parameters.AddWithValue(client.RequireConsent);
        cmd.Parameters.AddWithValue(client.AccessTokenLifetime ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(client.RefreshTokenLifetime ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(client.IsActive);
        cmd.Parameters.AddWithValue(client.CreatedAt);
        cmd.Parameters.AddWithValue(client.UpdatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task<IReadOnlyList<OAuthClient>> ListForTenantAsync(Guid tenantId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM oauth_clients
            WHERE tenant_id = $1
            ORDER BY created_at
            """;
        cmd.Parameters.AddWithValue(tenantId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var results = new List<OAuthClient>();
        while (await reader.ReadAsync(ct))
            results.Add(MapClient(reader));

        await session.CommitAsync(ct);
        return results.AsReadOnly();
    }

    private static OAuthClient MapClient(NpgsqlDataReader r) =>
        OAuthClient.Reconstitute(
            id: r.GetGuid(0),
            tenantId: r.GetGuid(1),
            clientId: r.GetString(2),
            clientSecretHash: r.IsDBNull(3) ? null : r.GetString(3),
            clientName: r.GetString(4),
            clientType: r.GetString(5),
            redirectUris: DeserializeStringList(r.GetString(6)),
            postLogoutRedirectUris: DeserializeStringList(r.GetString(7)),
            allowedScopes: DeserializeStringList(r.GetString(8)),
            allowedGrantTypes: DeserializeStringList(r.GetString(9)),
            requirePkce: r.GetBoolean(10),
            requireConsent: r.GetBoolean(11),
            accessTokenLifetime: r.IsDBNull(12) ? null : r.GetInt32(12),
            refreshTokenLifetime: r.IsDBNull(13) ? null : r.GetInt32(13),
            isActive: r.GetBoolean(14),
            createdAt: r.GetFieldValue<DateTimeOffset>(15),
            updatedAt: r.GetFieldValue<DateTimeOffset>(16)
        );

    private static IReadOnlyList<string> DeserializeStringList(string json) =>
        JsonSerializer.Deserialize<List<string>>(json)?.AsReadOnly()
        ?? (IReadOnlyList<string>)[];
}
