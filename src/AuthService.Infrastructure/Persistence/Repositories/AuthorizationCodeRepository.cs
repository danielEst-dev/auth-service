using System.Text.Json;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;
using NpgsqlTypes;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class AuthorizationCodeRepository(IDbSessionProvider sessions) : IAuthorizationCodeRepository
{
    private const string SelectColumns = """
        ac.id, ac.tenant_id, ac.code_hash,
        ac.client_id, oc.client_id AS client_id_str,
        ac.user_id, ac.redirect_uri, ac.scopes,
        ac.code_challenge, ac.code_challenge_method, ac.nonce,
        ac.issued_at, ac.expires_at, ac.is_redeemed
        """;

    public async Task<AuthorizationCode?> GetByCodeHashAsync(Guid tenantId, string codeHash, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM authorization_codes ac
            JOIN oauth_clients oc ON ac.client_id = oc.id
            WHERE ac.code_hash = $1 AND ac.tenant_id = $2
            """;
        cmd.Parameters.AddWithValue(codeHash);
        cmd.Parameters.AddWithValue(tenantId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapCode(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task CreateAsync(AuthorizationCode code, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(code.TenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO authorization_codes (
                id, tenant_id, code_hash, client_id, user_id,
                redirect_uri, scopes, code_challenge, code_challenge_method,
                nonce, issued_at, expires_at, is_redeemed
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, FALSE
            )
            """;

        cmd.Parameters.AddWithValue(code.Id);
        cmd.Parameters.AddWithValue(code.TenantId);
        cmd.Parameters.AddWithValue(code.CodeHash);
        cmd.Parameters.AddWithValue(code.ClientDbId);
        cmd.Parameters.AddWithValue(code.UserId);
        cmd.Parameters.AddWithValue(code.RedirectUri);
        cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = JsonSerializer.Serialize(code.Scopes) });
        cmd.Parameters.AddWithValue(code.CodeChallenge ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(code.CodeChallengeMethod);
        cmd.Parameters.AddWithValue(code.Nonce ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(code.IssuedAt);
        cmd.Parameters.AddWithValue(code.ExpiresAt);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task<bool> MarkRedeemedAsync(Guid tenantId, Guid id, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            UPDATE authorization_codes
            SET is_redeemed = TRUE
            WHERE id = $1 AND tenant_id = $2
              AND is_redeemed = FALSE AND expires_at > NOW()
            RETURNING id
            """;
        cmd.Parameters.AddWithValue(id);
        cmd.Parameters.AddWithValue(tenantId);

        var result = await cmd.ExecuteScalarAsync(ct);
        await session.CommitAsync(ct);
        return result is not null;
    }

    private static AuthorizationCode MapCode(NpgsqlDataReader r) =>
        AuthorizationCode.Reconstitute(
            id: r.GetGuid(0),
            tenantId: r.GetGuid(1),
            codeHash: r.GetString(2),
            clientDbId: r.GetGuid(3),
            clientId: r.GetString(4),
            userId: r.GetGuid(5),
            redirectUri: r.GetString(6),
            scopes: JsonSerializer.Deserialize<List<string>>(r.GetString(7))?.AsReadOnly()
                    ?? (IReadOnlyList<string>)[],
            codeChallenge: r.IsDBNull(8) ? null : r.GetString(8),
            codeChallengeMethod: r.GetString(9),
            nonce: r.IsDBNull(10) ? null : r.GetString(10),
            issuedAt: r.GetFieldValue<DateTimeOffset>(11),
            expiresAt: r.GetFieldValue<DateTimeOffset>(12),
            isRedeemed: r.GetBoolean(13)
        );
}
