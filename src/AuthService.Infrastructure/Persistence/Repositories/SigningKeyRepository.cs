using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;

namespace AuthService.Infrastructure.Persistence.Repositories;

/// <summary>
/// Repository for RSA signing keys. Global table — no tenant context, no RLS.
/// </summary>
public sealed class SigningKeyRepository(IDbSessionProvider sessions) : ISigningKeyRepository
{
    private const string SelectColumns = """
        id, kid, algorithm, private_key_encrypted, public_key_pem,
        is_active, activated_at, expires_at, created_at
        """;

    public async Task<SigningKey?> GetActiveAsync(CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM signing_keys
            WHERE is_active = TRUE
            ORDER BY activated_at DESC
            LIMIT 1
            """;

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapKey(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task<IReadOnlyList<SigningKey>> GetAllPublicAsync(CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM signing_keys
            WHERE expires_at IS NULL OR expires_at > NOW()
            ORDER BY activated_at DESC
            """;

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var results = new List<SigningKey>();
        while (await reader.ReadAsync(ct))
            results.Add(MapKey(reader));

        await session.CommitAsync(ct);
        return results.AsReadOnly();
    }

    public async Task CreateAsync(SigningKey key, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO signing_keys (
                id, kid, algorithm, private_key_encrypted, public_key_pem,
                is_active, activated_at, expires_at, created_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9
            )
            """;

        cmd.Parameters.AddWithValue(key.Id);
        cmd.Parameters.AddWithValue(key.Kid);
        cmd.Parameters.AddWithValue(key.Algorithm);
        cmd.Parameters.AddWithValue(key.PrivateKeyEncrypted);
        cmd.Parameters.AddWithValue(key.PublicKeyPem);
        cmd.Parameters.AddWithValue(key.IsActive);
        cmd.Parameters.AddWithValue(key.ActivatedAt);
        cmd.Parameters.AddWithValue(key.ExpiresAt ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(key.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task DeactivateAllAsync(CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = "UPDATE signing_keys SET is_active = FALSE";
        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    private static SigningKey MapKey(NpgsqlDataReader r) =>
        SigningKey.Reconstitute(
            id: r.GetGuid(0),
            kid: r.GetString(1),
            algorithm: r.GetString(2),
            privateKeyEncrypted: r.GetString(3),
            publicKeyPem: r.GetString(4),
            isActive: r.GetBoolean(5),
            activatedAt: r.GetFieldValue<DateTimeOffset>(6),
            expiresAt: r.IsDBNull(7) ? null : r.GetFieldValue<DateTimeOffset>(7),
            createdAt: r.GetFieldValue<DateTimeOffset>(8)
        );
}
