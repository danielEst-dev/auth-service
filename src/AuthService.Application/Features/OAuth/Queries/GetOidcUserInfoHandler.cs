using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;

namespace AuthService.Application.Features.OAuth.Queries;

public sealed class GetOidcUserInfoHandler(
    IUserRepository userRepository,
    ITokenService tokenService)
    : IQueryHandler<GetOidcUserInfoQuery, GetOidcUserInfoResult>
{
    public async Task<GetOidcUserInfoResult> HandleAsync(
        GetOidcUserInfoQuery query, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query.BearerToken))
            throw new OAuthException("invalid_token", "No Bearer token provided.", statusCode: 401);

        var principal = tokenService.ValidateAccessToken(query.BearerToken);
        if (principal is null)
            throw new OAuthException("invalid_token", "Token is invalid or expired.", statusCode: 401);

        var userIdStr   = principal.FindFirst("sub")?.Value;
        var tenantIdStr = principal.FindFirst("tenant_id")?.Value;
        var scopeClaim  = principal.FindFirst("scope")?.Value ?? string.Empty;
        var scopes      = scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (!Guid.TryParse(userIdStr, out var userId) || !Guid.TryParse(tenantIdStr, out var tenantId))
            throw new OAuthException("invalid_token", "Token is missing required claims.", statusCode: 401);

        var user = await userRepository.GetByIdAsync(tenantId, userId, ct);
        if (user is null || !user.IsActive)
            throw new OAuthException("invalid_token", "User not found or inactive.", statusCode: 401);

        var claims = new Dictionary<string, object>
        {
            ["sub"]       = user.Id.ToString(),
            ["tenant_id"] = tenantId.ToString(),
        };

        if (scopes.Contains("email", StringComparer.OrdinalIgnoreCase))
        {
            claims["email"]          = user.Email;
            claims["email_verified"] = user.IsEmailConfirmed;
        }

        if (scopes.Contains("profile", StringComparer.OrdinalIgnoreCase))
        {
            claims["preferred_username"] = user.Username;
            if (user.FirstName is not null) claims["given_name"]  = user.FirstName;
            if (user.LastName  is not null) claims["family_name"] = user.LastName;
        }

        return new GetOidcUserInfoResult(claims);
    }
}
