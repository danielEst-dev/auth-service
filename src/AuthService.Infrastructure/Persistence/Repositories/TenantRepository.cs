using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class TenantRepository(NpgsqlDataSource dataSource) : ITenantRepository
{
    public async Task<Tenant?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, slug, name, plan, custom_domain, is_active, is_system_tenant,
                   mfa_required, session_lifetime_minutes,
                   access_token_lifetime_seconds, refresh_token_lifetime_seconds,
                   created_at, updated_at
            FROM tenants
            WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(id);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? MapTenant(reader) : null;
    }

    public async Task<Tenant?> GetBySlugAsync(string slug, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, slug, name, plan, custom_domain, is_active, is_system_tenant,
                   mfa_required, session_lifetime_minutes,
                   access_token_lifetime_seconds, refresh_token_lifetime_seconds,
                   created_at, updated_at
            FROM tenants
            WHERE slug = $1 AND is_active = TRUE
            """;
        cmd.Parameters.AddWithValue(slug.ToLowerInvariant());

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? MapTenant(reader) : null;
    }

    public async Task<Tenant?> GetByCustomDomainAsync(string domain, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT id, slug, name, plan, custom_domain, is_active, is_system_tenant,
                   mfa_required, session_lifetime_minutes,
                   access_token_lifetime_seconds, refresh_token_lifetime_seconds,
                   created_at, updated_at
            FROM tenants
            WHERE custom_domain = $1 AND is_active = TRUE
            """;
        cmd.Parameters.AddWithValue(domain);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? MapTenant(reader) : null;
    }

    public async Task<bool> ExistsAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM tenants WHERE id = $1";
        cmd.Parameters.AddWithValue(id);
        return await cmd.ExecuteScalarAsync(ct) is not null;
    }

    public async Task<Guid> CreateAsync(Tenant tenant, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO tenants (
                id, slug, name, plan, custom_domain,
                is_active, is_system_tenant, mfa_required,
                session_lifetime_minutes, access_token_lifetime_seconds,
                refresh_token_lifetime_seconds, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8,
                $9, $10,
                $11, $12, $13
            )
            RETURNING id
            """;

        cmd.Parameters.AddWithValue(tenant.Id);
        cmd.Parameters.AddWithValue(tenant.Slug);
        cmd.Parameters.AddWithValue(tenant.Name);
        cmd.Parameters.AddWithValue(tenant.Plan);
        cmd.Parameters.AddWithValue(tenant.CustomDomain ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(tenant.IsActive);
        cmd.Parameters.AddWithValue(tenant.IsSystemTenant);
        cmd.Parameters.AddWithValue(tenant.MfaRequired);
        cmd.Parameters.AddWithValue(tenant.SessionLifetimeMinutes);
        cmd.Parameters.AddWithValue(tenant.AccessTokenLifetimeSeconds ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(tenant.RefreshTokenLifetimeSeconds ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(tenant.CreatedAt);
        cmd.Parameters.AddWithValue(tenant.UpdatedAt);

        var result = await cmd.ExecuteScalarAsync(ct);
        return (Guid)result!;
    }

    public async Task UpdateAsync(Tenant tenant, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE tenants SET
                name = $2,
                plan = $3,
                custom_domain = $4,
                is_active = $5,
                mfa_required = $6,
                session_lifetime_minutes = $7,
                access_token_lifetime_seconds = $8,
                refresh_token_lifetime_seconds = $9,
                updated_at = $10
            WHERE id = $1
            """;

        cmd.Parameters.AddWithValue(tenant.Id);
        cmd.Parameters.AddWithValue(tenant.Name);
        cmd.Parameters.AddWithValue(tenant.Plan);
        cmd.Parameters.AddWithValue(tenant.CustomDomain ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(tenant.IsActive);
        cmd.Parameters.AddWithValue(tenant.MfaRequired);
        cmd.Parameters.AddWithValue(tenant.SessionLifetimeMinutes);
        cmd.Parameters.AddWithValue(tenant.AccessTokenLifetimeSeconds ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(tenant.RefreshTokenLifetimeSeconds ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(tenant.UpdatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static Tenant MapTenant(NpgsqlDataReader reader) =>
        Tenant.Reconstitute(
            id: reader.GetGuid(0),
            slug: reader.GetString(1),
            name: reader.GetString(2),
            plan: reader.GetString(3),
            customDomain: reader.IsDBNull(4) ? null : reader.GetString(4),
            isActive: reader.GetBoolean(5),
            isSystemTenant: reader.GetBoolean(6),
            mfaRequired: reader.GetBoolean(7),
            sessionLifetimeMinutes: reader.GetInt32(8),
            accessTokenLifetimeSeconds: reader.IsDBNull(9) ? null : reader.GetInt32(9),
            refreshTokenLifetimeSeconds: reader.IsDBNull(10) ? null : reader.GetInt32(10),
            createdAt: reader.GetFieldValue<DateTimeOffset>(11),
            updatedAt: reader.GetFieldValue<DateTimeOffset>(12)
        );
}