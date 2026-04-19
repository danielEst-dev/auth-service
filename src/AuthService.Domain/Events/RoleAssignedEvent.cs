using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record RoleAssignedEvent(
    Guid UserId,
    Guid TenantId,
    Guid RoleId,
    string RoleName) : DomainEvent;