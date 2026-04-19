using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record MfaEnabledEvent(
    Guid UserId,
    Guid TenantId,
    string Method) : DomainEvent, ITenantScopedEvent;
