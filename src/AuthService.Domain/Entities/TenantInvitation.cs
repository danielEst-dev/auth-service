using AuthService.Domain.Common;
using AuthService.Domain.Events;

namespace AuthService.Domain.Entities;

public sealed class TenantInvitation : Entity
{
    public Guid TenantId { get; private set; }
    public string Email { get; private set; } = string.Empty;
    public string TokenHash { get; private set; } = string.Empty;
    public Guid? RoleId { get; private set; }
    public Guid? InvitedBy { get; private set; }
    public DateTimeOffset? AcceptedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    public bool IsExpired => ExpiresAt <= DateTimeOffset.UtcNow;
    public bool IsAccepted => AcceptedAt is not null;

    private TenantInvitation() { }

    public static TenantInvitation Create(
        Guid tenantId,
        string email,
        string tokenHash,
        Guid? roleId = null,
        Guid? invitedBy = null,
        TimeSpan? lifetime = null)
    {
        return new TenantInvitation
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            Email = email,
            TokenHash = tokenHash,
            RoleId = roleId,
            InvitedBy = invitedBy,
            ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime ?? TimeSpan.FromHours(48)),
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    public void Accept()
    {
        AcceptedAt = DateTimeOffset.UtcNow;
    }

    public static TenantInvitation Reconstitute(
        Guid id, Guid tenantId, string email, string tokenHash,
        Guid? roleId, Guid? invitedBy,
        DateTimeOffset? acceptedAt, DateTimeOffset expiresAt, DateTimeOffset createdAt)
    {
        return new TenantInvitation
        {
            Id = id,
            TenantId = tenantId,
            Email = email,
            TokenHash = tokenHash,
            RoleId = roleId,
            InvitedBy = invitedBy,
            AcceptedAt = acceptedAt,
            ExpiresAt = expiresAt,
            CreatedAt = createdAt
        };
    }
}