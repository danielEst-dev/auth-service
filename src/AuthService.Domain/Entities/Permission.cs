using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class Permission : Entity
{
    public Guid? TenantId { get; private set; }   // NULL = platform permission
    public string Name { get; private set; } = string.Empty;
    public string? Description { get; private set; }
    public string Resource { get; private set; } = string.Empty;
    public string Action { get; private set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; private set; }

    private Permission() { }

    public static Permission Create(string resource, string action, string? description = null, Guid? tenantId = null)
    {
        return new Permission
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            Name = $"{resource}:{action}",
            Description = description,
            Resource = resource,
            Action = action,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }
}