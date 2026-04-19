using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;

namespace AuthService.Application.Features.Auth.Commands;

public sealed class LogoutHandler(
    IRefreshTokenRepository refreshTokenRepository,
    ITokenService tokenService,
    ICacheService cacheService)
    : ICommandHandler<LogoutCommand, LogoutResult>
{
    public async Task<LogoutResult> HandleAsync(LogoutCommand command, CancellationToken ct = default)
    {
        // Blacklist the access token (if parseable). Idempotent: expired tokens produce a
        // negative expiry and are simply skipped.
        if (!string.IsNullOrWhiteSpace(command.AccessToken))
        {
            var principal = tokenService.ValidateAccessToken(command.AccessToken);
            if (principal is not null)
            {
                var jti = principal.FindFirst("jti")?.Value;
                var exp = principal.FindFirst("exp")?.Value;
                if (jti is not null && long.TryParse(exp, out var expUnix))
                {
                    var expiry = DateTimeOffset.FromUnixTimeSeconds(expUnix) - DateTimeOffset.UtcNow;
                    if (expiry > TimeSpan.Zero)
                        await cacheService.SetAsync($"blacklist:{jti}", "1", expiry, ct);
                }
            }
        }

        // Revoke the refresh token (if presented). Idempotent on already-revoked tokens.
        if (!string.IsNullOrWhiteSpace(command.RefreshToken))
        {
            var tokenHash = tokenService.HashRefreshToken(command.RefreshToken);
            var stored = await refreshTokenRepository.GetByTokenHashAsync(command.TenantId, tokenHash, ct);
            if (stored is not null && stored.IsActive)
            {
                stored.Revoke();
                await refreshTokenRepository.UpdateAsync(stored, ct);
            }
        }

        return new LogoutResult(true);
    }
}
