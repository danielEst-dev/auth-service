using AuthService.Application.Common.Interfaces;
using StackExchange.Redis;

namespace AuthService.Infrastructure.Cache;

public sealed class RedisCacheService : ICacheService
{
    private readonly IDatabase _db;

    public RedisCacheService(IConnectionMultiplexer redis)
    {
        _db = redis.GetDatabase();
    }

    public async Task<string?> GetAsync(string key, CancellationToken ct = default)
    {
        var value = await _db.StringGetAsync(key);
        return value.IsNullOrEmpty ? null : value.ToString();
    }

    public async Task SetAsync(string key, string value, TimeSpan? expiry = null, CancellationToken ct = default)
    {
        if (expiry.HasValue)
            await _db.StringSetAsync(key, value, expiry.Value);
        else
            await _db.StringSetAsync(key, value);
    }

    public async Task DeleteAsync(string key, CancellationToken ct = default)
    {
        await _db.KeyDeleteAsync(key);
    }

    public async Task<bool> ExistsAsync(string key, CancellationToken ct = default)
    {
        return await _db.KeyExistsAsync(key);
    }
}
