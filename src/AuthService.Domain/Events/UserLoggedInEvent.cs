using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record UserLoggedInEvent(
    Guid UserId,
    Guid TenantId,
    string? DeviceInfo) : DomainEvent, ITenantScopedEvent;