using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record PasswordChangedEvent(
    Guid UserId,
    Guid TenantId) : DomainEvent, ITenantScopedEvent;