using AuthService.Application.Common.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Grpc.Controllers;

/// <summary>
/// Handles GET /oauth/userinfo — Returns claims for the authenticated user.
/// Requires a valid OIDC access token (Bearer).
/// </summary>
[ApiController]
public sealed class UserInfoController(
    IUserRepository userRepository,
    ITokenService tokenService) : ControllerBase
{
    [HttpGet("/oauth/userinfo")]
    public async Task<IActionResult> GetUserInfo(CancellationToken ct)
    {
        var bearerToken = ExtractBearerToken();
        if (bearerToken is null)
            return Unauthorized(new { error = "invalid_token", error_description = "No Bearer token provided." });

        var principal = tokenService.ValidateAccessToken(bearerToken);
        if (principal is null)
            return Unauthorized(new { error = "invalid_token", error_description = "Token is invalid or expired." });

        var userIdStr   = principal.FindFirst("sub")?.Value;
        var tenantIdStr = principal.FindFirst("tenant_id")?.Value;
        var scopeClaim  = principal.FindFirst("scope")?.Value ?? string.Empty;
        var scopes      = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (!Guid.TryParse(userIdStr, out var userId) || !Guid.TryParse(tenantIdStr, out var tenantId))
            return Unauthorized(new { error = "invalid_token", error_description = "Token is missing required claims." });

        var user = await userRepository.GetByIdAsync(tenantId, userId, ct);
        if (user is null || !user.IsActive)
            return Unauthorized(new { error = "invalid_token", error_description = "User not found or inactive." });

        var claims = new Dictionary<string, object>
        {
            ["sub"]       = user.Id.ToString(),
            ["tenant_id"] = tenantId.ToString()
        };

        if (scopes.Contains("email", StringComparer.OrdinalIgnoreCase))
        {
            claims["email"]          = user.Email;
            claims["email_verified"] = user.IsEmailConfirmed;
        }

        if (scopes.Contains("profile", StringComparer.OrdinalIgnoreCase))
        {
            claims["preferred_username"] = user.Username;
            if (user.FirstName is not null) claims["given_name"]   = user.FirstName;
            if (user.LastName is not null)  claims["family_name"]  = user.LastName;
        }

        return Ok(claims);
    }

    private string? ExtractBearerToken()
    {
        var auth = Request.Headers.Authorization.FirstOrDefault();
        if (auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return auth["Bearer ".Length..].Trim();
        return null;
    }
}
