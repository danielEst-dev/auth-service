using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class UserRepository(NpgsqlDataSource dataSource) : IUserRepository
{
    private const string SelectColumns = """
        id, tenant_id, email, normalized_email, username, normalized_username,
        password_hash, first_name, last_name, phone_number, avatar_url,
        is_active, is_email_confirmed, is_phone_confirmed, is_locked_out,
        lockout_end_utc, failed_login_count, mfa_enabled,
        external_provider, external_provider_id,
        created_at, updated_at, last_login_at, password_changed_at
        """;

    public async Task<User?> GetByIdAsync(Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await SetTenantContext(conn, tenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM users
            WHERE id = $1 AND tenant_id = $2
            """;
        cmd.Parameters.AddWithValue(userId);
        cmd.Parameters.AddWithValue(tenantId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapUser(reader) : null;
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task<User?> GetByEmailAsync(Guid tenantId, string normalizedEmail, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await SetTenantContext(conn, tenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM users
            WHERE tenant_id = $1 AND normalized_email = $2
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(normalizedEmail);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapUser(reader) : null;
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task<User?> GetByUsernameAsync(Guid tenantId, string normalizedUsername, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await SetTenantContext(conn, tenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = $"""
            SELECT {SelectColumns}
            FROM users
            WHERE tenant_id = $1 AND normalized_username = $2
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(normalizedUsername);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapUser(reader) : null;
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task<bool> ExistsByEmailAsync(Guid tenantId, string normalizedEmail, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await SetTenantContext(conn, tenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT 1 FROM users WHERE tenant_id = $1 AND normalized_email = $2";
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(normalizedEmail);

        var result = await cmd.ExecuteScalarAsync(ct) is not null;
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task<bool> ExistsByUsernameAsync(Guid tenantId, string normalizedUsername, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await SetTenantContext(conn, tenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT 1 FROM users WHERE tenant_id = $1 AND normalized_username = $2";
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(normalizedUsername);

        var result = await cmd.ExecuteScalarAsync(ct) is not null;
        await tx.CommitAsync(ct);
        return result;
    }

    public async Task<Guid> CreateAsync(User user, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await SetTenantContext(conn, user.TenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO users (
                id, tenant_id, email, normalized_email, username, normalized_username,
                password_hash, first_name, last_name, phone_number,
                is_active, is_email_confirmed, is_phone_confirmed, is_locked_out,
                failed_login_count, mfa_enabled,
                external_provider, external_provider_id,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10,
                $11, $12, $13, $14,
                $15, $16,
                $17, $18,
                $19, $20
            )
            RETURNING id
            """;

        cmd.Parameters.AddWithValue(user.Id);
        cmd.Parameters.AddWithValue(user.TenantId);
        cmd.Parameters.AddWithValue(user.Email);
        cmd.Parameters.AddWithValue(user.NormalizedEmail);
        cmd.Parameters.AddWithValue(user.Username);
        cmd.Parameters.AddWithValue(user.NormalizedUsername);
        cmd.Parameters.AddWithValue(user.PasswordHash ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.FirstName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.LastName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.PhoneNumber ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.IsActive);
        cmd.Parameters.AddWithValue(user.IsEmailConfirmed);
        cmd.Parameters.AddWithValue(user.IsPhoneConfirmed);
        cmd.Parameters.AddWithValue(user.IsLockedOut);
        cmd.Parameters.AddWithValue(user.FailedLoginCount);
        cmd.Parameters.AddWithValue(user.MfaEnabled);
        cmd.Parameters.AddWithValue(user.ExternalProvider ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.ExternalProviderId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.CreatedAt);
        cmd.Parameters.AddWithValue(user.UpdatedAt);

        var result = await cmd.ExecuteScalarAsync(ct);
        await tx.CommitAsync(ct);
        return (Guid)result!;
    }

    public async Task UpdateAsync(User user, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await SetTenantContext(conn, user.TenantId, ct);

        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE users SET
                password_hash = $2,
                first_name = $3,
                last_name = $4,
                phone_number = $5,
                is_active = $6,
                is_email_confirmed = $7,
                is_locked_out = $8,
                lockout_end_utc = $9,
                failed_login_count = $10,
                mfa_enabled = $11,
                updated_at = $12,
                last_login_at = $13,
                password_changed_at = $14
            WHERE id = $1 AND tenant_id = $15
            """;

        cmd.Parameters.AddWithValue(user.Id);
        cmd.Parameters.AddWithValue(user.PasswordHash ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.FirstName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.LastName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.PhoneNumber ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.IsActive);
        cmd.Parameters.AddWithValue(user.IsEmailConfirmed);
        cmd.Parameters.AddWithValue(user.IsLockedOut);
        cmd.Parameters.AddWithValue(user.LockoutEndUtc ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.FailedLoginCount);
        cmd.Parameters.AddWithValue(user.MfaEnabled);
        cmd.Parameters.AddWithValue(user.UpdatedAt);
        cmd.Parameters.AddWithValue(user.LastLoginAt ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.PasswordChangedAt ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(user.TenantId);

        await cmd.ExecuteNonQueryAsync(ct);
        await tx.CommitAsync(ct);
    }

    private static async Task SetTenantContext(NpgsqlConnection conn, Guid tenantId, CancellationToken ct)
    {
        // SET LOCAL is transaction-scoped — requires an active transaction (BeginTransactionAsync)
        // to persist across subsequent commands. tenantId is a Guid so ToString() is injection-safe.
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SET LOCAL app.current_tenant_id = '{tenantId}'";
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static User MapUser(NpgsqlDataReader r) =>
        User.Reconstitute(
            id: r.GetGuid(0),
            tenantId: r.GetGuid(1),
            email: r.GetString(2),
            normalizedEmail: r.GetString(3),
            username: r.GetString(4),
            normalizedUsername: r.GetString(5),
            passwordHash: r.IsDBNull(6) ? null : r.GetString(6),
            firstName: r.IsDBNull(7) ? null : r.GetString(7),
            lastName: r.IsDBNull(8) ? null : r.GetString(8),
            phoneNumber: r.IsDBNull(9) ? null : r.GetString(9),
            avatarUrl: r.IsDBNull(10) ? null : r.GetString(10),
            isActive: r.GetBoolean(11),
            isEmailConfirmed: r.GetBoolean(12),
            isPhoneConfirmed: r.GetBoolean(13),
            isLockedOut: r.GetBoolean(14),
            lockoutEndUtc: r.IsDBNull(15) ? null : r.GetFieldValue<DateTimeOffset>(15),
            failedLoginCount: r.GetInt32(16),
            mfaEnabled: r.GetBoolean(17),
            externalProvider: r.IsDBNull(18) ? null : r.GetString(18),
            externalProviderId: r.IsDBNull(19) ? null : r.GetString(19),
            createdAt: r.GetFieldValue<DateTimeOffset>(20),
            updatedAt: r.GetFieldValue<DateTimeOffset>(21),
            lastLoginAt: r.IsDBNull(22) ? null : r.GetFieldValue<DateTimeOffset>(22),
            passwordChangedAt: r.IsDBNull(23) ? null : r.GetFieldValue<DateTimeOffset>(23)
        );
}