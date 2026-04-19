using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class OAuthClient : Entity
{
    public Guid TenantId { get; private set; }
    public string ClientId { get; private set; } = string.Empty;
    public string? ClientSecretHash { get; private set; }
    public string ClientName { get; private set; } = string.Empty;
    public string ClientType { get; private set; } = "confidential"; // confidential | public
    public IReadOnlyList<string> RedirectUris { get; private set; } = [];
    public IReadOnlyList<string> PostLogoutRedirectUris { get; private set; } = [];
    public IReadOnlyList<string> AllowedScopes { get; private set; } = [];
    public IReadOnlyList<string> AllowedGrantTypes { get; private set; } = [];
    public bool RequirePkce { get; private set; } = true;
    public bool RequireConsent { get; private set; }
    public int? AccessTokenLifetime { get; private set; }
    public int? RefreshTokenLifetime { get; private set; }
    public bool IsActive { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }

    private OAuthClient() { }

    public bool IsRedirectUriValid(string uri) =>
        RedirectUris.Contains(uri, StringComparer.Ordinal);

    public bool IsScopeAllowed(string scope) =>
        AllowedScopes.Contains(scope, StringComparer.Ordinal);

    public bool IsPublic => string.Equals(ClientType, "public", StringComparison.OrdinalIgnoreCase);

    public static OAuthClient Reconstitute(
        Guid id, Guid tenantId, string clientId, string? clientSecretHash,
        string clientName, string clientType,
        IReadOnlyList<string> redirectUris, IReadOnlyList<string> postLogoutRedirectUris,
        IReadOnlyList<string> allowedScopes, IReadOnlyList<string> allowedGrantTypes,
        bool requirePkce, bool requireConsent,
        int? accessTokenLifetime, int? refreshTokenLifetime,
        bool isActive, DateTimeOffset createdAt, DateTimeOffset updatedAt)
    {
        return new OAuthClient
        {
            Id = id,
            TenantId = tenantId,
            ClientId = clientId,
            ClientSecretHash = clientSecretHash,
            ClientName = clientName,
            ClientType = clientType,
            RedirectUris = redirectUris,
            PostLogoutRedirectUris = postLogoutRedirectUris,
            AllowedScopes = allowedScopes,
            AllowedGrantTypes = allowedGrantTypes,
            RequirePkce = requirePkce,
            RequireConsent = requireConsent,
            AccessTokenLifetime = accessTokenLifetime,
            RefreshTokenLifetime = refreshTokenLifetime,
            IsActive = isActive,
            CreatedAt = createdAt,
            UpdatedAt = updatedAt
        };
    }
}
