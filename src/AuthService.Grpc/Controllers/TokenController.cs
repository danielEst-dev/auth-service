using System.Security.Cryptography;
using System.Text;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Grpc.Controllers;

/// <summary>
/// POST /oauth/token — authorization_code and refresh_token grants. All JWT signing is
/// delegated to <see cref="ITokenService"/> so this controller stays an adapter.
/// </summary>
[ApiController]
public sealed class TokenController(
    IOAuthClientRepository clientRepository,
    IAuthorizationCodeRepository codeRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IPasswordHasher passwordHasher,
    ITokenService tokenService,
    ILogger<TokenController> logger) : ControllerBase
{
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);

    [HttpPost("/oauth/token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token([FromForm] IFormCollection form, CancellationToken ct)
    {
        var grantType = form["grant_type"].FirstOrDefault();
        return grantType switch
        {
            "authorization_code" => await HandleAuthorizationCodeAsync(form, ct),
            "refresh_token"      => await HandleRefreshTokenAsync(form, ct),
            _                    => OidcError("unsupported_grant_type", $"Grant type '{grantType}' is not supported.")
        };
    }

    // ── Authorization Code Grant ──────────────────────────────────────────────

    private async Task<IActionResult> HandleAuthorizationCodeAsync(IFormCollection form, CancellationToken ct)
    {
        var clientId     = form["client_id"].FirstOrDefault();
        var clientSecret = form["client_secret"].FirstOrDefault();
        var code         = form["code"].FirstOrDefault();
        var redirectUri  = form["redirect_uri"].FirstOrDefault();
        var codeVerifier = form["code_verifier"].FirstOrDefault();

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(code) || string.IsNullOrWhiteSpace(redirectUri))
            return OidcError("invalid_request", "client_id, code, and redirect_uri are required.");

        var client = await clientRepository.GetByClientIdAsync(clientId, ct);
        if (client is null || !client.IsActive)
            return OidcError("invalid_client", "Unknown or inactive client.");

        if (!client.IsPublic)
        {
            if (string.IsNullOrWhiteSpace(clientSecret) || client.ClientSecretHash is null
                || !passwordHasher.Verify(clientSecret, client.ClientSecretHash))
                return OidcError("invalid_client", "Client authentication failed.");
        }

        var codeHash = HashCode(code);
        var authCode = await codeRepository.GetByCodeHashAsync(client.TenantId, codeHash, ct);
        if (authCode is null || authCode.IsExpired || authCode.IsRedeemed)
            return OidcError("invalid_grant", "Authorization code is invalid or expired.");

        if (!string.Equals(authCode.RedirectUri, redirectUri, StringComparison.Ordinal))
            return OidcError("invalid_grant", "redirect_uri does not match.");

        if (!string.Equals(authCode.ClientId, clientId, StringComparison.Ordinal))
            return OidcError("invalid_grant", "Code was not issued to this client.");

        if (client.RequirePkce || authCode.CodeChallenge is not null)
        {
            if (string.IsNullOrWhiteSpace(codeVerifier))
                return OidcError("invalid_grant", "code_verifier is required.");

            var hashBytes = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
            var computedChallenge = Base64UrlEncoder.Encode(hashBytes);

            if (!string.Equals(computedChallenge, authCode.CodeChallenge, StringComparison.Ordinal))
                return OidcError("invalid_grant", "PKCE verification failed.");
        }

        var redeemed = await codeRepository.MarkRedeemedAsync(client.TenantId, authCode.Id, ct);
        if (!redeemed)
            return OidcError("invalid_grant", "Authorization code has already been used.");

        var tenant = await tenantRepository.GetByIdAsync(client.TenantId, ct);
        if (tenant is null)
            return OidcError("server_error", "Tenant not found.");

        var user = await userRepository.GetByIdAsync(client.TenantId, authCode.UserId, ct);
        if (user is null || !user.IsActive)
            return OidcError("invalid_grant", "User account is inactive or not found.");

        var (accessToken, expiresIn) = tokenService.IssueOidcAccessToken(user, tenant, client, authCode.Scopes);
        var idToken = tokenService.IssueIdToken(user, tenant, client, authCode.Scopes, authCode.Nonce);

        string? rawRefresh = null;
        if (authCode.Scopes.Contains("offline_access", StringComparer.OrdinalIgnoreCase))
        {
            rawRefresh = tokenService.GenerateRawRefreshToken();
            var tokenHash = tokenService.HashRefreshToken(rawRefresh);
            var refreshToken = RefreshToken.Create(
                tenantId:   client.TenantId,
                userId:     user.Id,
                tokenHash:  tokenHash,
                jti:        Guid.CreateVersion7().ToString(),
                lifetime:   GetRefreshTokenLifetime(tenant, client));
            await refreshTokenRepository.CreateAsync(refreshToken, ct);
        }

        logger.LogInformation(
            "OIDC tokens issued for user {UserId} client {ClientId} tenant {TenantId}",
            user.Id, clientId, client.TenantId);

        var response = new Dictionary<string, object?>
        {
            ["access_token"] = accessToken,
            ["token_type"]   = "Bearer",
            ["expires_in"]   = expiresIn,
            ["id_token"]     = idToken,
            ["scope"]        = string.Join(' ', authCode.Scopes),
        };
        if (rawRefresh is not null) response["refresh_token"] = rawRefresh;

        return Ok(response);
    }

    // ── Refresh Token Grant ───────────────────────────────────────────────────

    private async Task<IActionResult> HandleRefreshTokenAsync(IFormCollection form, CancellationToken ct)
    {
        var clientId     = form["client_id"].FirstOrDefault();
        var clientSecret = form["client_secret"].FirstOrDefault();
        var rawToken     = form["refresh_token"].FirstOrDefault();

        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(rawToken))
            return OidcError("invalid_request", "client_id and refresh_token are required.");

        var client = await clientRepository.GetByClientIdAsync(clientId, ct);
        if (client is null || !client.IsActive)
            return OidcError("invalid_client", "Unknown or inactive client.");

        if (!client.IsPublic)
        {
            if (string.IsNullOrWhiteSpace(clientSecret) || client.ClientSecretHash is null
                || !passwordHasher.Verify(clientSecret, client.ClientSecretHash))
                return OidcError("invalid_client", "Client authentication failed.");
        }

        var tokenHash = tokenService.HashRefreshToken(rawToken);
        var stored    = await refreshTokenRepository.GetByTokenHashAsync(client.TenantId, tokenHash, ct);

        if (stored is null || !stored.IsActive)
        {
            if (stored is not null)
            {
                logger.LogWarning("Refresh token reuse detected for user {UserId} — revoking all", stored.UserId);
                await refreshTokenRepository.RevokeAllForUserAsync(client.TenantId, stored.UserId, ct);
            }
            return OidcError("invalid_grant", "Refresh token is invalid or expired.");
        }

        var tenant = await tenantRepository.GetByIdAsync(client.TenantId, ct);
        if (tenant is null)
            return OidcError("server_error", "Tenant not found.");

        var user = await userRepository.GetByIdAsync(client.TenantId, stored.UserId, ct);
        if (user is null || !user.IsActive)
            return OidcError("invalid_grant", "User account is inactive.");

        var newRaw  = tokenService.GenerateRawRefreshToken();
        var newHash = tokenService.HashRefreshToken(newRaw);
        var replacement = stored.Rotate(newHash, Guid.CreateVersion7().ToString(), GetRefreshTokenLifetime(tenant, client));

        await refreshTokenRepository.UpdateAsync(stored, ct);
        await refreshTokenRepository.CreateAsync(replacement, ct);

        // Per OIDC spec, no new ID token on refresh — access token only
        var (accessToken, expiresIn) = tokenService.IssueOidcAccessToken(user, tenant, client, ["openid"]);

        return Ok(new
        {
            access_token  = accessToken,
            token_type    = "Bearer",
            expires_in    = expiresIn,
            refresh_token = newRaw,
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string HashCode(string rawCode) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawCode))).ToLowerInvariant();

    private static TimeSpan GetRefreshTokenLifetime(Tenant tenant, OAuthClient client)
    {
        if (client.RefreshTokenLifetime.HasValue)
            return TimeSpan.FromSeconds(client.RefreshTokenLifetime.Value);
        if (tenant.RefreshTokenLifetimeSeconds.HasValue)
            return TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value);
        return DefaultRefreshTokenLifetime;
    }

    private IActionResult OidcError(string error, string description) =>
        BadRequest(new { error, error_description = description });
}
