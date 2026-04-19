using System.Text.Json;
using AuthService.Application.Common.Interfaces;

namespace AuthService.Infrastructure.Cache;

public sealed class PermissionCacheService(ICacheService cacheService) : IPermissionCacheService
{
    private static readonly TimeSpan DefaultExpiry = TimeSpan.FromMinutes(15);

    public async Task<CachedPermissions?> GetPermissionsAsync(
        Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        var key  = CacheKey(tenantId, userId);
        var json = await cacheService.GetAsync(key, ct);
        if (json is null) return null;

        try
        {
            return JsonSerializer.Deserialize<CachedPermissions>(json);
        }
        catch
        {
            // Corrupt cache entry — delete and return miss
            await cacheService.DeleteAsync(key, ct);
            return null;
        }
    }

    public async Task SetPermissionsAsync(
        Guid tenantId, Guid userId, CachedPermissions permissions, CancellationToken ct = default)
    {
        var key  = CacheKey(tenantId, userId);
        var json = JsonSerializer.Serialize(permissions);
        await cacheService.SetAsync(key, json, DefaultExpiry, ct);
    }

    public async Task InvalidatePermissionsAsync(
        Guid tenantId, Guid userId, CancellationToken ct = default)
    {
        await cacheService.DeleteAsync(CacheKey(tenantId, userId), ct);
    }

    private static string CacheKey(Guid tenantId, Guid userId)
        => $"permissions:{tenantId}:{userId}";
}