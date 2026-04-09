using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Common;

namespace AuthService.Infrastructure.Messaging;

/// <summary>
/// Dispatches all pending domain events from an entity to the event publisher,
/// then clears the entity's event list.
/// </summary>
public sealed class DomainEventDispatcher(IEventPublisher publisher)
{
    public async Task DispatchAndClearAsync(Entity entity, CancellationToken ct = default)
    {
        foreach (var domainEvent in entity.DomainEvents)
            await publisher.PublishAsync(domainEvent, ct);

        entity.ClearDomainEvents();
    }
}
