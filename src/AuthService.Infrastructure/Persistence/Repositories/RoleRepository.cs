using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Npgsql;

namespace AuthService.Infrastructure.Persistence.Repositories;

public sealed class RoleRepository(IDbSessionProvider sessions) : IRoleRepository
{
    public async Task<IReadOnlyList<string>> GetRoleNamesForUserAsync(
        Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.tenant_id = $1
              AND ur.user_id   = $2
            ORDER BY r.name
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(userId);

        var roles = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            roles.Add(reader.GetString(0));

        await session.CommitAsync(ct);
        return roles;
    }

    public async Task<IReadOnlyList<string>> GetPermissionNamesForUserAsync(
        Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT DISTINCT p.name
            FROM user_roles ur
            JOIN role_permissions rp ON rp.role_id = ur.role_id
            JOIN permissions p       ON p.id = rp.permission_id
            WHERE ur.tenant_id = $1
              AND ur.user_id   = $2
            ORDER BY p.name
            """;
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(userId);

        var permissions = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            permissions.Add(reader.GetString(0));

        await session.CommitAsync(ct);
        return permissions;
    }

    public async Task<Role?> GetByIdAsync(Guid tenantId, Guid roleId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {RoleColumns}
            FROM roles
            WHERE id = $1
              AND (tenant_id = $2 OR tenant_id IS NULL)
            """;
        cmd.Parameters.AddWithValue(roleId);
        cmd.Parameters.AddWithValue(tenantId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapRole(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task<Role?> GetByNameAsync(Guid tenantId, string normalizedName, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {RoleColumns}
            FROM roles
            WHERE normalized_name = $1
              AND (tenant_id = $2 OR tenant_id IS NULL)
            LIMIT 1
            """;
        cmd.Parameters.AddWithValue(normalizedName);
        cmd.Parameters.AddWithValue(tenantId);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var result = await reader.ReadAsync(ct) ? MapRole(reader) : null;
        await session.CommitAsync(ct);
        return result;
    }

    public async Task<IReadOnlyList<Role>> ListForTenantAsync(Guid tenantId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = $"""
            SELECT {RoleColumns}
            FROM roles
            WHERE tenant_id = $1 OR tenant_id IS NULL
            ORDER BY is_system_role DESC, name
            """;
        cmd.Parameters.AddWithValue(tenantId);

        var roles = new List<Role>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            roles.Add(MapRole(reader));

        await session.CommitAsync(ct);
        return roles;
    }

    public async Task<Guid> CreateAsync(Role role, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(role.TenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO roles (id, tenant_id, name, normalized_name, description, is_system_role, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            """;
        cmd.Parameters.AddWithValue(role.Id);
        cmd.Parameters.AddWithValue(role.TenantId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(role.Name);
        cmd.Parameters.AddWithValue(role.NormalizedName);
        cmd.Parameters.AddWithValue(role.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(role.IsSystemRole);
        cmd.Parameters.AddWithValue(role.CreatedAt);
        cmd.Parameters.AddWithValue(role.UpdatedAt);

        var result = await cmd.ExecuteScalarAsync(ct);
        await session.CommitAsync(ct);
        return (Guid)result!;
    }

    public async Task AssignRoleAsync(
        Guid tenantId, Guid userId, Guid roleId, Guid? assignedBy, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO user_roles (user_id, role_id, tenant_id, assigned_by)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, role_id) DO NOTHING
            """;
        cmd.Parameters.AddWithValue(userId);
        cmd.Parameters.AddWithValue(roleId);
        cmd.Parameters.AddWithValue(tenantId);
        cmd.Parameters.AddWithValue(assignedBy ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task UnassignRoleAsync(
        Guid tenantId, Guid userId, Guid roleId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            DELETE FROM user_roles
            WHERE user_id = $1 AND role_id = $2 AND tenant_id = $3
            """;
        cmd.Parameters.AddWithValue(userId);
        cmd.Parameters.AddWithValue(roleId);
        cmd.Parameters.AddWithValue(tenantId);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }

    public async Task<bool> UserHasRoleAsync(
        Guid tenantId, Guid userId, Guid roleId, CancellationToken ct = default)
    {
        await using var session = await sessions.GetSessionAsync(tenantId, ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            SELECT 1 FROM user_roles
            WHERE user_id = $1 AND role_id = $2 AND tenant_id = $3
            """;
        cmd.Parameters.AddWithValue(userId);
        cmd.Parameters.AddWithValue(roleId);
        cmd.Parameters.AddWithValue(tenantId);

        var result = await cmd.ExecuteScalarAsync(ct) is not null;
        await session.CommitAsync(ct);
        return result;
    }

    private const string RoleColumns =
        "id, tenant_id, name, normalized_name, description, is_system_role, created_at, updated_at";

    private static Role MapRole(NpgsqlDataReader r) =>
        r.IsDBNull(1)
            ? Role.ReconstituteSystemRole(
                id:             r.GetGuid(0),
                name:           r.GetString(2),
                normalizedName: r.GetString(3),
                description:    r.IsDBNull(4) ? null : r.GetString(4),
                createdAt:      r.GetFieldValue<DateTimeOffset>(6),
                updatedAt:      r.GetFieldValue<DateTimeOffset>(7))
            : Role.ReconstituteTenantRole(
                id:             r.GetGuid(0),
                tenantId:       r.GetGuid(1),
                name:           r.GetString(2),
                normalizedName: r.GetString(3),
                description:    r.IsDBNull(4) ? null : r.GetString(4),
                createdAt:      r.GetFieldValue<DateTimeOffset>(6),
                updatedAt:      r.GetFieldValue<DateTimeOffset>(7));
}
