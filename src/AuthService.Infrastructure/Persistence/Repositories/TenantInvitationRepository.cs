using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class TenantInvitationRepository(IDbSessionProvider sessions) : ITenantInvitationRepository
{
    public async Task<TenantInvitation?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT id, tenant_id, email, token_hash, role_id, invited_by,
                   accepted_at, expires_at, created_at
            FROM tenant_invitations
            WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(id);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapInvitation(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task<TenantInvitation?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT id, tenant_id, email, token_hash, role_id, invited_by,
                   accepted_at, expires_at, created_at
            FROM tenant_invitations
            WHERE token_hash = $1
            """;
        cmd.Parameters.AddWithValue(tokenHash);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapInvitation(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task CreateAsync(TenantInvitation invitation, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(invitation.TenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO tenant_invitations (id, tenant_id, email, token_hash, role_id, invited_by, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """;
        cmd.Parameters.AddWithValue(invitation.Id);
        cmd.Parameters.AddWithValue(invitation.TenantId);
        cmd.Parameters.AddWithValue(invitation.Email);
        cmd.Parameters.AddWithValue(invitation.TokenHash);
        cmd.Parameters.AddWithValue(invitation.RoleId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(invitation.InvitedBy ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(invitation.ExpiresAt);
        cmd.Parameters.AddWithValue(invitation.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task UpdateAsync(TenantInvitation invitation, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(invitation.TenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            UPDATE tenant_invitations SET accepted_at = $2
            WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(invitation.Id);
        cmd.Parameters.AddWithValue(invitation.AcceptedAt ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task<bool> ExistsForEmailAsync(Guid tenantId, string email, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT 1 FROM tenant_invitations
            WHERE tenant_id = $1 AND email = $2 AND accepted_at IS NULL AND expires_at > NOW()
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(email);

        var result = await cmd.ExecuteScalarAsync(ct) is not null;
        await session.CommitAsync(ct);
        return result;
    }

    private static TenantInvitation MapInvitation(NpgsqlDataReader r) =>
        TenantInvitation.Reconstitute(
            id: r.GetGuid(0),
            tenantId: r.GetGuid(1),
            email: r.GetString(2),
            tokenHash: r.GetString(3),
            roleId: r.IsDBNull(4) ? null : r.GetGuid(4),
            invitedBy: r.IsDBNull(5) ? null : r.GetGuid(5),
            acceptedAt: r.IsDBNull(6) ? null : r.GetFieldValue<DateTimeOffset>(6),
            expiresAt: r.GetFieldValue<DateTimeOffset>(7),
            createdAt: r.GetFieldValue<DateTimeOffset>(8));
}
