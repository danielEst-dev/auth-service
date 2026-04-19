using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record AccountLockedEvent(
    Guid UserId,
    Guid TenantId,
    int FailedAttempts) : DomainEvent, ITenantScopedEvent;