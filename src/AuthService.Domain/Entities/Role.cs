using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class Role : Entity
{
    public Guid? TenantId { get; private set; }   // NULL = system role
    public string Name { get; private set; } = string.Empty;
    public string NormalizedName { get; private set; } = string.Empty;
    public string? Description { get; private set; }
    public bool IsSystemRole { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }

    private Role() { }

    public static Role CreateTenantRole(Guid tenantId, string name, string? description = null)
    {
        return new Role
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            Name = name,
            NormalizedName = name.ToUpperInvariant(),
            Description = description,
            IsSystemRole = false,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
    }

    public static Role CreateSystemRole(string name, string? description = null)
    {
        return new Role
        {
            Id = Guid.CreateVersion7(),
            TenantId = null,
            Name = name,
            NormalizedName = name.ToUpperInvariant(),
            Description = description,
            IsSystemRole = true,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };
    }

    public static Role ReconstituteTenantRole(
        Guid id, Guid tenantId, string name, string normalizedName,
        string? description, DateTimeOffset createdAt, DateTimeOffset updatedAt)
    {
        return new Role
        {
            Id = id,
            TenantId = tenantId,
            Name = name,
            NormalizedName = normalizedName,
            Description = description,
            IsSystemRole = false,
            CreatedAt = createdAt,
            UpdatedAt = updatedAt
        };
    }

    public static Role ReconstituteSystemRole(
        Guid id, string name, string normalizedName,
        string? description, DateTimeOffset createdAt, DateTimeOffset updatedAt)
    {
        return new Role
        {
            Id = id,
            TenantId = null,
            Name = name,
            NormalizedName = normalizedName,
            Description = description,
            IsSystemRole = true,
            CreatedAt = createdAt,
            UpdatedAt = updatedAt
        };
    }
}