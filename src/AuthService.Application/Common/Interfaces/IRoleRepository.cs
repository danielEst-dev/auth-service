using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IRoleRepository
{
    /// <summary>Returns all role names assigned to a user (system roles + tenant roles).</summary>
    Task<IReadOnlyList<string>> GetRoleNamesForUserAsync(Guid tenantId, Guid userId, CancellationToken ct = default);

    /// <summary>Returns all permission names for a user (via their roles).</summary>
    Task<IReadOnlyList<string>> GetPermissionNamesForUserAsync(Guid tenantId, Guid userId, CancellationToken ct = default);

    Task<Role?> GetByIdAsync(Guid tenantId, Guid roleId, CancellationToken ct = default);
    Task<Role?> GetByNameAsync(Guid tenantId, string normalizedName, CancellationToken ct = default);

    /// <summary>Returns all roles visible to a tenant (tenant roles + system roles).</summary>
    Task<IReadOnlyList<Role>> ListForTenantAsync(Guid tenantId, CancellationToken ct = default);

    Task<Guid> CreateAsync(Role role, CancellationToken ct = default);

    Task AssignRoleAsync(Guid tenantId, Guid userId, Guid roleId, Guid? assignedBy, CancellationToken ct = default);
    Task UnassignRoleAsync(Guid tenantId, Guid userId, Guid roleId, CancellationToken ct = default);

    Task<bool> UserHasRoleAsync(Guid tenantId, Guid userId, Guid roleId, CancellationToken ct = default);
}
