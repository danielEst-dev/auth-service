using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Common;

namespace AuthService.Infrastructure.Messaging;

/// <summary>
/// Drains queued domain events from an entity into the outbox. Direct publishing is
/// replaced by durable enqueue — the <see cref="OutboxRelay"/> does the actual transport
/// publish. This decouples commit-time from publish-time and survives broker outages.
/// </summary>
public sealed class DomainEventDispatcher(IOutboxWriter outbox) : IDomainEventDispatcher
{
    public async Task DispatchAndClearAsync(Entity entity, CancellationToken ct = default)
    {
        foreach (var domainEvent in entity.DomainEvents)
            await outbox.WriteAsync(domainEvent, ct);

        entity.ClearDomainEvents();
    }
}
