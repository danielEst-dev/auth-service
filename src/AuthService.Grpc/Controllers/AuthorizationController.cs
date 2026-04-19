using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Grpc.Controllers;

/// <summary>
/// Handles GET /oauth/authorize — Authorization Code flow with PKCE.
/// Tenant is resolved from the OAuth client record (cross-tenant client_id lookup).
/// User must be pre-authenticated via gRPC Login and present their access token as Bearer.
/// </summary>
[ApiController]
public sealed class AuthorizationController(
    IOAuthClientRepository clientRepository,
    IAuthorizationCodeRepository codeRepository,
    IUserConsentRepository consentRepository,
    ITokenService tokenService,
    ILogger<AuthorizationController> logger) : ControllerBase
{
    [HttpGet("/oauth/authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery(Name = "client_id")]             string? clientId,
        [FromQuery(Name = "redirect_uri")]          string? redirectUri,
        [FromQuery(Name = "response_type")]         string? responseType,
        [FromQuery(Name = "scope")]                 string? scope,
        [FromQuery(Name = "state")]                 string? state,
        [FromQuery(Name = "code_challenge")]        string? codeChallenge,
        [FromQuery(Name = "code_challenge_method")] string? codeChallengeMethod,
        [FromQuery(Name = "nonce")]                 string? nonce,
        CancellationToken ct)
    {
        // ── Basic parameter validation ────────────────────────────────────────

        if (string.IsNullOrWhiteSpace(clientId))
            return OidcError("invalid_request", "client_id is required", redirectUri, state);

        if (!string.Equals(responseType, "code", StringComparison.OrdinalIgnoreCase))
            return OidcError("unsupported_response_type", "Only response_type=code is supported", redirectUri, state);

        if (string.IsNullOrWhiteSpace(redirectUri))
            return OidcError("invalid_request", "redirect_uri is required", null, state);

        // ── Resolve client (cross-tenant) ─────────────────────────────────────

        var client = await clientRepository.GetByClientIdAsync(clientId, ct);
        if (client is null || !client.IsActive)
            return OidcError("invalid_client", "Unknown or inactive client", redirectUri, state);

        if (!client.IsRedirectUriValid(redirectUri))
            return OidcError("invalid_request", "redirect_uri is not registered for this client", redirectUri, state);

        // ── Scope validation ──────────────────────────────────────────────────

        var requestedScopes = (scope ?? "openid").Split(' ', StringSplitOptions.RemoveEmptyEntries);

        foreach (var s in requestedScopes)
        {
            if (!client.IsScopeAllowed(s))
                return OidcError("invalid_scope", $"Scope '{s}' is not allowed for this client", redirectUri, state);
        }

        // ── PKCE validation ───────────────────────────────────────────────────

        if (client.RequirePkce)
        {
            if (string.IsNullOrWhiteSpace(codeChallenge))
                return OidcError("invalid_request", "code_challenge is required (PKCE)", redirectUri, state);

            if (!string.Equals(codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
                return OidcError("invalid_request", "Only code_challenge_method=S256 is supported", redirectUri, state);
        }

        // ── Authenticate the user (Bearer token from gRPC login) ─────────────

        var bearerToken = ExtractBearerToken();
        if (bearerToken is null)
            return OidcError("login_required", "No authentication token provided. Log in via the auth service first.", redirectUri, state, statusCode: 401);

        var principal = tokenService.ValidateAccessToken(bearerToken);
        if (principal is null)
            return OidcError("login_required", "Authentication token is invalid or expired.", redirectUri, state, statusCode: 401);

        var userIdStr = principal.FindFirst("sub")?.Value;
        var tokenTenantId = principal.FindFirst("tenant_id")?.Value;

        if (!Guid.TryParse(userIdStr, out var userId))
            return OidcError("login_required", "Invalid user identity in token.", redirectUri, state, statusCode: 401);

        // Cross-check: the JWT's tenant must match the client's tenant
        if (!Guid.TryParse(tokenTenantId, out var jwtTenantId) || jwtTenantId != client.TenantId)
            return OidcError("access_denied", "Token tenant does not match client tenant.", redirectUri, state, statusCode: 403);

        // ── Consent check ─────────────────────────────────────────────────────

        if (client.RequireConsent)
        {
            var consent = await consentRepository.GetAsync(client.TenantId, userId, client.Id, ct);
            if (consent is null || consent.IsExpired || !consent.CoversScopes(requestedScopes))
                return OidcError("consent_required",
                    "User has not granted consent for the requested scopes.",
                    redirectUri, state, statusCode: 403);
        }

        // ── Issue authorization code ──────────────────────────────────────────

        var rawCode = GenerateRawCode();
        var codeHash = HashCode(rawCode);

        var authCode = AuthorizationCode.Create(
            tenantId: client.TenantId,
            clientDbId: client.Id,
            clientId: client.ClientId,
            userId: userId,
            codeHash: codeHash,
            redirectUri: redirectUri,
            scopes: requestedScopes,
            codeChallenge: codeChallenge,
            nonce: nonce,
            codeChallengeMethod: codeChallengeMethod ?? "S256",
            lifetimeSeconds: 300);

        await codeRepository.CreateAsync(authCode, ct);

        logger.LogInformation(
            "Authorization code issued for user {UserId} client {ClientId} tenant {TenantId}",
            userId, clientId, client.TenantId);

        // Redirect with code
        var callbackUri = BuildCallbackUri(redirectUri, rawCode, state);
        return Redirect(callbackUri);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private string? ExtractBearerToken()
    {
        var auth = Request.Headers.Authorization.FirstOrDefault();
        if (auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return auth["Bearer ".Length..].Trim();
        return null;
    }

    private static string GenerateRawCode()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static string HashCode(string rawCode)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(rawCode);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    private static string BuildCallbackUri(string redirectUri, string code, string? state)
    {
        var uri = $"{redirectUri}?code={Uri.EscapeDataString(code)}";
        if (!string.IsNullOrWhiteSpace(state))
            uri += $"&state={Uri.EscapeDataString(state)}";
        return uri;
    }

    private IActionResult OidcError(
        string error,
        string description,
        string? redirectUri,
        string? state,
        int statusCode = 400)
    {
        // If we have a valid redirect_uri, redirect with error params (RFC 6749 §4.1.2.1)
        if (!string.IsNullOrWhiteSpace(redirectUri))
        {
            var uri = $"{redirectUri}?error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(description)}";
            if (!string.IsNullOrWhiteSpace(state))
                uri += $"&state={Uri.EscapeDataString(state)}";
            return Redirect(uri);
        }

        // No redirect_uri — return JSON error directly
        Response.StatusCode = statusCode;
        return new JsonResult(new { error, error_description = description });
    }
}
