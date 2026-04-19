using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record UserRegisteredEvent(
    Guid UserId,
    Guid TenantId,
    string Email) : DomainEvent, ITenantScopedEvent;