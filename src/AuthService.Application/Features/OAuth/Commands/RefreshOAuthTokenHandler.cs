using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.OAuth.Commands;

public sealed class RefreshOAuthTokenHandler(
    IOAuthClientRepository clientRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    ILogger<RefreshOAuthTokenHandler> logger)
    : ICommandHandler<RefreshOAuthTokenCommand, TokenExchangeResult>
{
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);

    public async Task<TokenExchangeResult> HandleAsync(
        RefreshOAuthTokenCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.ClientId) || string.IsNullOrWhiteSpace(command.RefreshToken))
            throw new OAuthException("invalid_request", "client_id and refresh_token are required.");

        var client = await clientRepository.GetByClientIdAsync(command.ClientId, ct);
        if (client is null || !client.IsActive)
            throw new OAuthException("invalid_client", "Unknown or inactive client.");

        if (!client.IsPublic)
        {
            if (string.IsNullOrWhiteSpace(command.ClientSecret)
                || client.ClientSecretHash is null
                || !passwordHasher.Verify(command.ClientSecret, client.ClientSecretHash))
            {
                throw new OAuthException("invalid_client", "Client authentication failed.");
            }
        }

        var tokenHash = tokenService.HashRefreshToken(command.RefreshToken);
        var stored    = await refreshTokenRepository.GetByTokenHashAsync(client.TenantId, tokenHash, ct);

        // Reuse detection: a revoked token being replayed means a copy leaked. Burn the family.
        if (stored is null || !stored.IsActive)
        {
            if (stored is not null)
            {
                logger.LogWarning(
                    "Refresh token reuse detected for user {UserId} — revoking all", stored.UserId);
                await refreshTokenRepository.RevokeAllForUserAsync(client.TenantId, stored.UserId, ct);
            }
            throw new OAuthException("invalid_grant", "Refresh token is invalid or expired.");
        }

        var tenant = await tenantRepository.GetByIdAsync(client.TenantId, ct)
            ?? throw new OAuthException("server_error", "Tenant not found.", statusCode: 500);

        var user = await userRepository.GetByIdAsync(client.TenantId, stored.UserId, ct);
        if (user is null || !user.IsActive)
            throw new OAuthException("invalid_grant", "User account is inactive.");

        // Rotate: revoke the presented token, link to its replacement.
        var newRaw      = tokenService.GenerateRawRefreshToken();
        var newHash     = tokenService.HashRefreshToken(newRaw);
        var replacement = stored.Rotate(newHash, Guid.CreateVersion7().ToString(), Lifetime(tenant, client));

        await refreshTokenRepository.UpdateAsync(stored, ct);
        await refreshTokenRepository.CreateAsync(replacement, ct);

        // Per OIDC Core §12, no new ID token on refresh — access token only.
        var (accessToken, expiresIn) = tokenService.IssueOidcAccessToken(user, tenant, client, ["openid"]);

        return new TokenExchangeResult(
            AccessToken:  accessToken,
            TokenType:    "Bearer",
            ExpiresIn:    expiresIn,
            IdToken:      null,
            RefreshToken: newRaw,
            Scope:        "openid");
    }

    private static TimeSpan Lifetime(Tenant tenant, OAuthClient client)
    {
        if (client.RefreshTokenLifetime.HasValue)
            return TimeSpan.FromSeconds(client.RefreshTokenLifetime.Value);
        if (tenant.RefreshTokenLifetimeSeconds.HasValue)
            return TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value);
        return DefaultRefreshTokenLifetime;
    }
}
