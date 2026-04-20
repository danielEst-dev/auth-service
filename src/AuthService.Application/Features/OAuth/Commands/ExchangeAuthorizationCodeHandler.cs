using System.Security.Cryptography;
using System.Text;
using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Common.Security;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.OAuth.Commands;

public sealed class ExchangeAuthorizationCodeHandler(
    IOAuthClientRepository clientRepository,
    IAuthorizationCodeRepository codeRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    ILogger<ExchangeAuthorizationCodeHandler> logger)
    : ICommandHandler<ExchangeAuthorizationCodeCommand, TokenExchangeResult>
{
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);

    public async Task<TokenExchangeResult> HandleAsync(
        ExchangeAuthorizationCodeCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.ClientId)
            || string.IsNullOrWhiteSpace(command.Code)
            || string.IsNullOrWhiteSpace(command.RedirectUri))
        {
            throw new OAuthException("invalid_request", "client_id, code, and redirect_uri are required.");
        }

        // ── Authenticate client ───────────────────────────────────────────────

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

        // ── Look up the auth code ─────────────────────────────────────────────

        var codeHash = OpaqueToken.Hash(command.Code);
        var authCode = await codeRepository.GetByCodeHashAsync(client.TenantId, codeHash, ct);
        if (authCode is null || authCode.IsExpired || authCode.IsRedeemed)
            throw new OAuthException("invalid_grant", "Authorization code is invalid or expired.");

        if (!string.Equals(authCode.RedirectUri, command.RedirectUri, StringComparison.Ordinal))
            throw new OAuthException("invalid_grant", "redirect_uri does not match.");

        if (!string.Equals(authCode.ClientId, command.ClientId, StringComparison.Ordinal))
            throw new OAuthException("invalid_grant", "Code was not issued to this client.");

        // ── PKCE ──────────────────────────────────────────────────────────────

        if (client.RequirePkce || authCode.CodeChallenge is not null)
        {
            if (string.IsNullOrWhiteSpace(command.CodeVerifier))
                throw new OAuthException("invalid_grant", "code_verifier is required.");

            // PKCE §4.6: challenge = BASE64URL(SHA256(ASCII(verifier))) — no padding.
            var hashBytes = SHA256.HashData(Encoding.ASCII.GetBytes(command.CodeVerifier));
            var computed  = Convert.ToBase64String(hashBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
            if (!string.Equals(computed, authCode.CodeChallenge, StringComparison.Ordinal))
                throw new OAuthException("invalid_grant", "PKCE verification failed.");
        }

        // ── Atomic redeem — one-shot enforcement ──────────────────────────────

        if (!await codeRepository.MarkRedeemedAsync(client.TenantId, authCode.Id, ct))
            throw new OAuthException("invalid_grant", "Authorization code has already been used.");

        // ── Load tenant + user, issue tokens ──────────────────────────────────

        var tenant = await tenantRepository.GetByIdAsync(client.TenantId, ct)
            ?? throw new OAuthException("server_error", "Tenant not found.", statusCode: 500);

        var user = await userRepository.GetByIdAsync(client.TenantId, authCode.UserId, ct);
        if (user is null || !user.IsActive)
            throw new OAuthException("invalid_grant", "User account is inactive or not found.");

        var (accessToken, expiresIn) = tokenService.IssueOidcAccessToken(user, tenant, client, authCode.Scopes);
        var idToken = tokenService.IssueIdToken(user, tenant, client, authCode.Scopes, authCode.Nonce);

        string? rawRefresh = null;
        if (authCode.Scopes.Contains("offline_access", StringComparer.OrdinalIgnoreCase))
        {
            rawRefresh = tokenService.GenerateRawRefreshToken();
            var refreshToken = RefreshToken.Create(
                tenantId:   client.TenantId,
                userId:     user.Id,
                tokenHash:  tokenService.HashRefreshToken(rawRefresh),
                jti:        Guid.CreateVersion7().ToString(),
                lifetime:   Lifetime(tenant, client));
            await refreshTokenRepository.CreateAsync(refreshToken, ct);
        }

        logger.LogInformation(
            "OIDC tokens issued for user {UserId} client {ClientId} tenant {TenantId}",
            user.Id, command.ClientId, client.TenantId);

        return new TokenExchangeResult(
            AccessToken:  accessToken,
            TokenType:    "Bearer",
            ExpiresIn:    expiresIn,
            IdToken:      idToken,
            RefreshToken: rawRefresh,
            Scope:        string.Join(' ', authCode.Scopes));
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
