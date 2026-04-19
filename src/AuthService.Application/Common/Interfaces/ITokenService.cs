using System.Security.Claims;
using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public sealed record TokenPair(
    string AccessToken,
    string RefreshToken,
    DateTimeOffset AccessTokenExpiry,
    DateTimeOffset RefreshTokenExpiry);

public interface ITokenService
{
    // ── gRPC / internal access tokens ─────────────────────────────────────────

    TokenPair GenerateTokenPair(
        User user,
        Tenant tenant,
        IEnumerable<string> roles,
        IEnumerable<string> permissions);

    ClaimsPrincipal? ValidateAccessToken(string token);

    // ── OIDC access + ID tokens ───────────────────────────────────────────────

    /// <summary>
    /// Issues an OIDC access token (scope-based, audience = client_id).
    /// Lifetime is client override → tenant override → service default.
    /// </summary>
    (string Token, int ExpiresInSeconds) IssueOidcAccessToken(
        User user, Tenant tenant, OAuthClient client, IEnumerable<string> scopes);

    /// <summary>
    /// Issues an OIDC ID token (scope-driven claim set, audience = client_id, nonce echoed).
    /// </summary>
    string IssueIdToken(
        User user, Tenant tenant, OAuthClient client,
        IEnumerable<string> scopes, string? nonce);

    // ── Refresh tokens ────────────────────────────────────────────────────────

    string HashRefreshToken(string rawToken);
    string GenerateRawRefreshToken();
}
