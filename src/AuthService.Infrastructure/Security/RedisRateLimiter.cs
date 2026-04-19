using AuthService.Application.Common.Interfaces;
using StackExchange.Redis;

namespace AuthService.Infrastructure.Security;

/// <summary>
/// Fixed-window rate limiter backed by Redis. INCR + PEXPIRE are executed atomically via
/// a Lua script so the TTL is always set on the first hit — avoiding the classic
/// "INCR succeeded but EXPIRE didn't run" bug that leaves counters without TTL.
/// </summary>
public sealed class RedisRateLimiter(IConnectionMultiplexer redis) : IRateLimiter
{
    // KEYS[1] = counter key, ARGV[1] = window in ms.
    // Returns {current, pttl}. PEXPIRE is only set when the counter was freshly created.
    private static readonly LuaScript Script = LuaScript.Prepare(
        """
        local current = redis.call('INCR', @key)
        if current == 1 then
          redis.call('PEXPIRE', @key, @windowMs)
        end
        return {current, redis.call('PTTL', @key)}
        """);

    public async Task<RateLimitResult> CheckAsync(
        string key, int limit, TimeSpan window, CancellationToken ct = default)
    {
        var db = redis.GetDatabase();
        var result = (RedisResult[])(await db.ScriptEvaluateAsync(Script, new { key = (RedisKey)key, windowMs = (long)window.TotalMilliseconds }))!;

        var current = (long)result[0];
        var pttl    = (long)result[1];
        var retryAfter = pttl > 0 ? TimeSpan.FromMilliseconds(pttl) : window;

        return new RateLimitResult(
            Allowed: current <= limit,
            Current: current,
            Limit:   limit,
            RetryAfter: retryAfter);
    }
}
