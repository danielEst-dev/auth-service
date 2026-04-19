namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Fixed-window request counter keyed by an arbitrary string. Intended for abuse prevention
/// (brute-force login, MFA guessing, password-reset flooding) — not for fair-share scheduling.
/// </summary>
public interface IRateLimiter
{
    /// <summary>
    /// Atomically increments the counter at <paramref name="key"/> and returns whether the
    /// request is under <paramref name="limit"/>. The counter resets <paramref name="window"/>
    /// after its first increment.
    /// </summary>
    Task<RateLimitResult> CheckAsync(
        string key,
        int limit,
        TimeSpan window,
        CancellationToken ct = default);
}

public sealed record RateLimitResult(bool Allowed, long Current, int Limit, TimeSpan RetryAfter);
