using AuthService.Domain.Common;

namespace AuthService.Domain.Events;

public sealed record TenantInvitationAcceptedEvent(
    Guid InvitationId,
    Guid TenantId,
    Guid UserId,
    string Email) : DomainEvent, ITenantScopedEvent;