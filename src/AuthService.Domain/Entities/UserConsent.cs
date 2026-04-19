using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class UserConsent : Entity
{
    public Guid TenantId { get; private set; }
    public Guid UserId { get; private set; }
    public Guid ClientDbId { get; private set; }  // FK to oauth_clients.id
    public IReadOnlyList<string> Scopes { get; private set; } = [];
    public DateTimeOffset GrantedAt { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }

    private UserConsent() { }

    public bool CoversScopes(IEnumerable<string> requested) =>
        requested.All(s => Scopes.Contains(s, StringComparer.Ordinal));

    public bool IsExpired => ExpiresAt.HasValue && DateTimeOffset.UtcNow >= ExpiresAt.Value;

    public static UserConsent Create(
        Guid tenantId,
        Guid userId,
        Guid clientDbId,
        IEnumerable<string> scopes,
        TimeSpan? lifetime = null)
    {
        var now = DateTimeOffset.UtcNow;
        return new UserConsent
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            UserId = userId,
            ClientDbId = clientDbId,
            Scopes = scopes.ToList().AsReadOnly(),
            GrantedAt = now,
            ExpiresAt = lifetime.HasValue ? now.Add(lifetime.Value) : null
        };
    }

    public static UserConsent Reconstitute(
        Guid id, Guid tenantId, Guid userId, Guid clientDbId,
        IReadOnlyList<string> scopes,
        DateTimeOffset grantedAt, DateTimeOffset? expiresAt)
    {
        return new UserConsent
        {
            Id = id,
            TenantId = tenantId,
            UserId = userId,
            ClientDbId = clientDbId,
            Scopes = scopes,
            GrantedAt = grantedAt,
            ExpiresAt = expiresAt
        };
    }
}
