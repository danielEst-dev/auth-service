using AuthService.Domain.Common;
using AuthService.Domain.Events;

namespace AuthService.Domain.Entities;

public sealed class Tenant : Entity
{
    public string Slug { get; private set; } = string.Empty;
    public string Name { get; private set; } = string.Empty;
    public string Plan { get; private set; } = "free";
    public string? CustomDomain { get; private set; }
    public bool IsActive { get; private set; } = true;
    public bool IsSystemTenant { get; private set; }
    public bool MfaRequired { get; private set; }
    public int SessionLifetimeMinutes { get; private set; } = 60;
    public int? AccessTokenLifetimeSeconds { get; private set; }
    public int? RefreshTokenLifetimeSeconds { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }

    private Tenant() { }

    public static Tenant Create(string slug, string name, string plan = "free")
    {
        var tenant = new Tenant
        {
            Id = Guid.CreateVersion7(),
            Slug = slug.ToLowerInvariant(),
            Name = name,
            Plan = plan,
            IsActive = true,
            IsSystemTenant = false,
            MfaRequired = false,
            SessionLifetimeMinutes = 60,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        tenant.AddDomainEvent(new TenantCreatedEvent(tenant.Id, tenant.Slug, tenant.Name));
        return tenant;
    }

    public void UpdateName(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Name = name;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void Deactivate()
    {
        IsActive = false;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void Activate()
    {
        IsActive = true;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void SetCustomDomain(string? customDomain)
    {
        CustomDomain = customDomain;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void RequireMfa(bool required)
    {
        MfaRequired = required;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    // Used by repositories to rehydrate from persistence — does not raise domain events
    public static Tenant Reconstitute(
        Guid id, string slug, string name, string plan,
        string? customDomain, bool isActive, bool isSystemTenant,
        bool mfaRequired, int sessionLifetimeMinutes,
        int? accessTokenLifetimeSeconds, int? refreshTokenLifetimeSeconds,
        DateTimeOffset createdAt, DateTimeOffset updatedAt)
    {
        return new Tenant
        {
            Id = id,
            Slug = slug,
            Name = name,
            Plan = plan,
            CustomDomain = customDomain,
            IsActive = isActive,
            IsSystemTenant = isSystemTenant,
            MfaRequired = mfaRequired,
            SessionLifetimeMinutes = sessionLifetimeMinutes,
            AccessTokenLifetimeSeconds = accessTokenLifetimeSeconds,
            RefreshTokenLifetimeSeconds = refreshTokenLifetimeSeconds,
            CreatedAt = createdAt,
            UpdatedAt = updatedAt
        };
    }
}