using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record TenantCreatedEvent(
    Guid TenantId,
    string Slug,
    string Name) : DomainEvent, ITenantScopedEvent;