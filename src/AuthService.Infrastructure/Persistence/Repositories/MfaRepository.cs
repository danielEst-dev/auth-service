using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class MfaRepository(IDbSessionProvider sessions) : IMfaRepository
{
    // ── MfaSecret ─────────────────────────────────────────────────────────────

    public async Task<MfaSecret?> GetSecretByUserIdAsync(Guid userId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT id, user_id, secret_encrypted, method, is_confirmed, created_at
            FROM mfa_secrets
            WHERE user_id = $1
            """;
        cmd.Parameters.AddWithValue(userId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapSecret(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task CreateSecretAsync(MfaSecret secret, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO mfa_secrets (id, user_id, secret_encrypted, method, is_confirmed, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, method) DO UPDATE
                SET secret_encrypted = EXCLUDED.secret_encrypted,
                    is_confirmed = EXCLUDED.is_confirmed
            """;
        cmd.Parameters.AddWithValue(secret.Id);
        cmd.Parameters.AddWithValue(secret.UserId);
        cmd.Parameters.AddWithValue(secret.SecretEncrypted);
        cmd.Parameters.AddWithValue(secret.Method);
        cmd.Parameters.AddWithValue(secret.IsConfirmed);
        cmd.Parameters.AddWithValue(secret.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task UpdateSecretAsync(MfaSecret secret, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            UPDATE mfa_secrets SET is_confirmed = $2
            WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(secret.Id);
        cmd.Parameters.AddWithValue(secret.IsConfirmed);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task DeleteSecretAsync(Guid userId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = "DELETE FROM mfa_secrets WHERE user_id = $1";
        cmd.Parameters.AddWithValue(userId);
        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    // ── MfaRecoveryCode ───────────────────────────────────────────────────────

    public async Task<IReadOnlyList<MfaRecoveryCode>> GetRecoveryCodesAsync(Guid userId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT id, user_id, code_hash, is_used, used_at, created_at
            FROM mfa_recovery_codes
            WHERE user_id = $1
            """;
        cmd.Parameters.AddWithValue(userId);

        var results = new List<MfaRecoveryCode>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            results.Add(MapRecoveryCode(reader));
        await session.CommitAsync(ct);
        return results;
    }

    public async Task CreateRecoveryCodesAsync(IEnumerable<MfaRecoveryCode> codes, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        foreach (var code in codes)
        {
            await using var cmd = session.Connection.CreateCommand();
            cmd.Transaction = session.Transaction;
            cmd.CommandText = """
                INSERT INTO mfa_recovery_codes (id, user_id, code_hash, is_used, created_at)
                VALUES ($1, $2, $3, $4, $5)
                """;
            cmd.Parameters.AddWithValue(code.Id);
            cmd.Parameters.AddWithValue(code.UserId);
            cmd.Parameters.AddWithValue(code.CodeHash);
            cmd.Parameters.AddWithValue(code.IsUsed);
            cmd.Parameters.AddWithValue(code.CreatedAt);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await session.CommitAsync(ct);
    }

    public async Task MarkRecoveryCodeUsedAsync(Guid codeId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            UPDATE mfa_recovery_codes SET is_used = TRUE, used_at = NOW()
            WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(codeId);
        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task<MfaRecoveryCode?> GetUnusedRecoveryCodeByHashAsync(
        Guid userId, string codeHash, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT id, user_id, code_hash, is_used, used_at, created_at
            FROM mfa_recovery_codes
            WHERE user_id = $1 AND code_hash = $2 AND is_used = FALSE
            """;
        cmd.Parameters.AddWithValue(userId);
        cmd.Parameters.AddWithValue(codeHash);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapRecoveryCode(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task DeleteRecoveryCodesAsync(Guid userId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = "DELETE FROM mfa_recovery_codes WHERE user_id = $1";
        cmd.Parameters.AddWithValue(userId);
        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    // ── Mappers ───────────────────────────────────────────────────────────────

    private static MfaSecret MapSecret(NpgsqlDataReader r) =>
        MfaSecret.Reconstitute(
            id: r.GetGuid(0),
            userId: r.GetGuid(1),
            secretEncrypted: r.GetString(2),
            method: r.GetString(3),
            isConfirmed: r.GetBoolean(4),
            createdAt: r.GetFieldValue<DateTimeOffset>(5));

    private static MfaRecoveryCode MapRecoveryCode(NpgsqlDataReader r) =>
        MfaRecoveryCode.Reconstitute(
            id: r.GetGuid(0),
            userId: r.GetGuid(1),
            codeHash: r.GetString(2),
            isUsed: r.GetBoolean(3),
            usedAt: r.IsDBNull(4) ? null : r.GetFieldValue<DateTimeOffset>(4),
            createdAt: r.GetFieldValue<DateTimeOffset>(5));
}
