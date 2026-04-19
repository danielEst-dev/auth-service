using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IOAuthClientRepository
{
    /// <summary>Cross-tenant lookup by string client_id. Used at /oauth/authorize before tenant context is known.</summary>
    Task<OAuthClient?> GetByClientIdAsync(string clientId, CancellationToken ct = default);

    Task<OAuthClient?> GetByIdAsync(Guid tenantId, Guid id, CancellationToken ct = default);

    Task CreateAsync(OAuthClient client, CancellationToken ct = default);

    Task<IReadOnlyList<OAuthClient>> ListForTenantAsync(Guid tenantId, CancellationToken ct = default);
}
