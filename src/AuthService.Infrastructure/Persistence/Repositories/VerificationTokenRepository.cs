using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class VerificationTokenRepository(IDbSessionProvider sessions) : IVerificationTokenRepository
{
    public async Task<VerificationToken?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT id, user_id, token_hash, purpose, issued_at, expires_at, is_used, used_at
            FROM verification_tokens
            WHERE token_hash = $1
            """;
        cmd.Parameters.AddWithValue(tokenHash);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapToken(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task CreateAsync(VerificationToken token, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO verification_tokens (id, user_id, token_hash, purpose, issued_at, expires_at, is_used)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """;
        cmd.Parameters.AddWithValue(token.Id);
        cmd.Parameters.AddWithValue(token.UserId);
        cmd.Parameters.AddWithValue(token.TokenHash);
        cmd.Parameters.AddWithValue(token.Purpose);
        cmd.Parameters.AddWithValue(token.IssuedAt);
        cmd.Parameters.AddWithValue(token.ExpiresAt);
        cmd.Parameters.AddWithValue(token.IsUsed);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task MarkUsedAsync(Guid tokenId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            UPDATE verification_tokens SET is_used = TRUE, used_at = NOW()
            WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(tokenId);
        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    private static VerificationToken MapToken(NpgsqlDataReader r) =>
        VerificationToken.Reconstitute(
            id: r.GetGuid(0),
            userId: r.GetGuid(1),
            tokenHash: r.GetString(2),
            purpose: r.GetString(3),
            issuedAt: r.GetFieldValue<DateTimeOffset>(4),
            expiresAt: r.GetFieldValue<DateTimeOffset>(5),
            isUsed: r.GetBoolean(6),
            usedAt: r.IsDBNull(7) ? null : r.GetFieldValue<DateTimeOffset>(7));
}
