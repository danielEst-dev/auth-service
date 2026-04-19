namespace AuthService.Application.Common.Interfaces;

public interface IPermissionCacheService
{
    Task<CachedPermissions?> GetPermissionsAsync(Guid tenantId, Guid userId, CancellationToken ct = default);
    Task SetPermissionsAsync(Guid tenantId, Guid userId, CachedPermissions permissions, CancellationToken ct = default);
    Task InvalidatePermissionsAsync(Guid tenantId, Guid userId, CancellationToken ct = default);
}

public sealed record CachedPermissions(
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions);