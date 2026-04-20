using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Common.Security;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.OAuth.Commands;

public sealed class AuthorizeHandler(
    IOAuthClientRepository clientRepository,
    IAuthorizationCodeRepository codeRepository,
    IUserConsentRepository consentRepository,
    ITokenService tokenService,
    ILogger<AuthorizeHandler> logger)
    : ICommandHandler<AuthorizeCommand, AuthorizeResult>
{
    private const int AuthCodeLifetimeSeconds = 300;

    public async Task<AuthorizeResult> HandleAsync(AuthorizeCommand command, CancellationToken ct = default)
    {
        // ── Stage 1: errors BEFORE the redirect_uri is trusted ────────────────
        // Per RFC 6749 §4.1.2.1, these must NOT redirect — we can't trust the URI.

        if (string.IsNullOrWhiteSpace(command.ClientId))
            throw new OAuthException("invalid_request", "client_id is required");

        if (!string.Equals(command.ResponseType, "code", StringComparison.OrdinalIgnoreCase))
            throw new OAuthException("unsupported_response_type",
                "Only response_type=code is supported", command.RedirectUri, command.State);

        if (string.IsNullOrWhiteSpace(command.RedirectUri))
            throw new OAuthException("invalid_request", "redirect_uri is required");

        var client = await clientRepository.GetByClientIdAsync(command.ClientId, ct);
        if (client is null || !client.IsActive)
            throw new OAuthException("invalid_client", "Unknown or inactive client");

        if (!client.IsRedirectUriValid(command.RedirectUri))
            throw new OAuthException("invalid_request", "redirect_uri is not registered for this client");

        // From here on, the redirect_uri is trusted — error redirects are safe.

        // ── Stage 2: scope + PKCE ─────────────────────────────────────────────

        var requestedScopes = (command.Scope ?? "openid").Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var s in requestedScopes)
        {
            if (!client.IsScopeAllowed(s))
                throw new OAuthException("invalid_scope",
                    $"Scope '{s}' is not allowed for this client", command.RedirectUri, command.State);
        }

        if (client.RequirePkce)
        {
            if (string.IsNullOrWhiteSpace(command.CodeChallenge))
                throw new OAuthException("invalid_request",
                    "code_challenge is required (PKCE)", command.RedirectUri, command.State);
            if (!string.Equals(command.CodeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
                throw new OAuthException("invalid_request",
                    "Only code_challenge_method=S256 is supported", command.RedirectUri, command.State);
        }

        // ── Stage 3: authenticate the caller ──────────────────────────────────
        // Phase O3 will replace this with a 302 to a configured login URL.
        // Until then, callers must present a gRPC-issued access token as Bearer.

        if (string.IsNullOrWhiteSpace(command.CallerAccessToken))
            throw new OAuthException("login_required",
                "No authentication token provided. Log in via the auth service first.",
                command.RedirectUri, command.State, statusCode: 401);

        var principal = tokenService.ValidateAccessToken(command.CallerAccessToken);
        if (principal is null)
            throw new OAuthException("login_required",
                "Authentication token is invalid or expired.",
                command.RedirectUri, command.State, statusCode: 401);

        var userIdStr     = principal.FindFirst("sub")?.Value;
        var tokenTenantId = principal.FindFirst("tenant_id")?.Value;

        if (!Guid.TryParse(userIdStr, out var userId))
            throw new OAuthException("login_required",
                "Invalid user identity in token.",
                command.RedirectUri, command.State, statusCode: 401);

        // Cross-tenant guard: a token minted for tenant A must not authorize a client in tenant B.
        if (!Guid.TryParse(tokenTenantId, out var jwtTenantId) || jwtTenantId != client.TenantId)
            throw new OAuthException("access_denied",
                "Token tenant does not match client tenant.",
                command.RedirectUri, command.State, statusCode: 403);

        // ── Stage 4: consent ──────────────────────────────────────────────────

        if (client.RequireConsent)
        {
            var consent = await consentRepository.GetAsync(client.TenantId, userId, client.Id, ct);
            if (consent is null || consent.IsExpired || !consent.CoversScopes(requestedScopes))
                throw new OAuthException("consent_required",
                    "User has not granted consent for the requested scopes.",
                    command.RedirectUri, command.State, statusCode: 403);
        }

        // ── Stage 5: issue authorization code ─────────────────────────────────

        var rawCode  = OpaqueToken.Generate();
        var codeHash = OpaqueToken.Hash(rawCode);

        var authCode = AuthorizationCode.Create(
            tenantId:            client.TenantId,
            clientDbId:          client.Id,
            clientId:            client.ClientId,
            userId:              userId,
            codeHash:            codeHash,
            redirectUri:         command.RedirectUri,
            scopes:              requestedScopes,
            codeChallenge:       command.CodeChallenge,
            nonce:               command.Nonce,
            codeChallengeMethod: command.CodeChallengeMethod ?? "S256",
            lifetimeSeconds:     AuthCodeLifetimeSeconds);

        await codeRepository.CreateAsync(authCode, ct);

        logger.LogInformation(
            "Authorization code issued for user {UserId} client {ClientId} tenant {TenantId}",
            userId, command.ClientId, client.TenantId);

        return new AuthorizeResult(BuildCallbackUri(command.RedirectUri, rawCode, command.State));
    }

    private static string BuildCallbackUri(string redirectUri, string code, string? state)
    {
        var uri = $"{redirectUri}?code={Uri.EscapeDataString(code)}";
        if (!string.IsNullOrWhiteSpace(state))
            uri += $"&state={Uri.EscapeDataString(state)}";
        return uri;
    }
}
