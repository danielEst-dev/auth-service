using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;

namespace AuthService.Application.Features.Verification.Commands;

/// <summary>Shared IP-based throttle for the verification/reset token submission surface.</summary>
internal static class VerificationRateLimits
{
    public static async Task EnforceAsync(
        IRateLimiter rateLimiter, Guid tenantId, string peerIp,
        int limit, TimeSpan window, CancellationToken ct)
    {
        var key = $"rl:vtoken:{tenantId}:{peerIp}";
        var rl = await rateLimiter.CheckAsync(key, limit, window, ct);
        if (!rl.Allowed) throw new RateLimitedException(rl.RetryAfter);
    }
}
