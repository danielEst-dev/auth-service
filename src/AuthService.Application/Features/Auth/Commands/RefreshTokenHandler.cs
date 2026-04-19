using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Auth.Commands;

public sealed class RefreshTokenHandler(
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IRoleRepository roleRepository,
    ITokenService tokenService,
    IRateLimiter rateLimiter,
    ILogger<RefreshTokenHandler> logger)
    : ICommandHandler<RefreshTokenCommand, RefreshTokenResult>
{
    private const int RefreshLimit = 60;
    private static readonly TimeSpan RefreshWindow = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);

    public async Task<RefreshTokenResult> HandleAsync(RefreshTokenCommand command, CancellationToken ct = default)
    {
        var rl = await rateLimiter.CheckAsync(
            $"rl:refresh:{command.TenantId}:{command.PeerIp}", RefreshLimit, RefreshWindow, ct);
        if (!rl.Allowed) throw new RateLimitedException(rl.RetryAfter);

        var tenant = await tenantRepository.GetByIdAsync(command.TenantId, ct)
            ?? throw new NotFoundException("Tenant not found.");

        var tokenHash = tokenService.HashRefreshToken(command.RefreshToken);
        var stored = await refreshTokenRepository.GetByTokenHashAsync(command.TenantId, tokenHash, ct);

        if (stored is null)
            throw new AuthenticationException("Refresh token is invalid or expired.");

        // Reuse detection: a revoked token being replayed means someone has (or had) a copy.
        // Revoke the entire family to force re-authentication across all devices.
        if (!stored.IsActive)
        {
            logger.LogWarning(
                "Refresh token reuse detected for user {UserId} in tenant {TenantId} — revoking all tokens",
                stored.UserId, command.TenantId);
            await refreshTokenRepository.RevokeAllForUserAsync(command.TenantId, stored.UserId, ct);
            throw new AuthenticationException("Refresh token has been revoked. Please log in again.");
        }

        var user = await userRepository.GetByIdAsync(command.TenantId, stored.UserId, ct)
            ?? throw new NotFoundException("User not found.");

        if (!user.IsActive)
            throw new AuthorizationException("Account is inactive.");

        var roles       = await roleRepository.GetRoleNamesForUserAsync(command.TenantId, user.Id, ct);
        var permissions = await roleRepository.GetPermissionNamesForUserAsync(command.TenantId, user.Id, ct);
        var newPair     = tokenService.GenerateTokenPair(user, tenant, roles, permissions);

        var newHash     = tokenService.HashRefreshToken(newPair.RefreshToken);
        var replacement = stored.Rotate(newHash, Guid.CreateVersion7().ToString(), Lifetime(tenant));

        await refreshTokenRepository.UpdateAsync(stored, ct);
        await refreshTokenRepository.CreateAsync(replacement, ct);

        return new RefreshTokenResult(
            AccessToken:        newPair.AccessToken,
            RefreshToken:       newPair.RefreshToken,
            AccessTokenExpiry:  newPair.AccessTokenExpiry,
            RefreshTokenExpiry: newPair.RefreshTokenExpiry);
    }

    private static TimeSpan Lifetime(Tenant tenant) =>
        tenant.RefreshTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value)
            : DefaultRefreshTokenLifetime;
}
