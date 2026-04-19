using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;

namespace AuthService.Application.Features.Auth.Queries;

public sealed class ValidateTokenHandler(
    ITokenService tokenService,
    ICacheService cacheService)
    : IQueryHandler<ValidateTokenQuery, ValidateTokenResult>
{
    public async Task<ValidateTokenResult> HandleAsync(ValidateTokenQuery query, CancellationToken ct = default)
    {
        var principal = tokenService.ValidateAccessToken(query.AccessToken);
        if (principal is null)
            return ValidateTokenResult.Invalid();

        // Cross-check: the token's embedded tenant must match the resolved request tenant.
        // Otherwise a leaked token from tenant A could be replayed against tenant B.
        var tokenTenantId = principal.FindFirst("tenant_id")?.Value;
        if (tokenTenantId is null
            || !Guid.TryParse(tokenTenantId, out var parsedTenantId)
            || parsedTenantId != query.RequestTenantId)
        {
            return ValidateTokenResult.Invalid();
        }

        // Revocation check — logout blacklists the jti.
        var jti = principal.FindFirst("jti")?.Value;
        if (jti is not null && await cacheService.ExistsAsync($"blacklist:{jti}", ct))
            return ValidateTokenResult.Invalid();

        return new ValidateTokenResult(
            IsValid:     true,
            UserId:      principal.FindFirst("sub")?.Value ?? string.Empty,
            TenantId:    tokenTenantId,
            Roles:       principal.FindAll("role").Select(c => c.Value).ToList(),
            Permissions: principal.FindAll("permission").Select(c => c.Value).ToList());
    }
}
