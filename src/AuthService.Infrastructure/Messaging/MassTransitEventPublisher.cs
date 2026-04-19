using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Common;
using Microsoft.Extensions.Logging;

namespace AuthService.Infrastructure.Messaging;

/// <summary>
/// Durable event publisher. Routes through the outbox instead of directly to MassTransit
/// so publishes survive broker outages and app restarts. Callers that previously used
/// <see cref="IEventPublisher"/> for ad-hoc events (e.g. <c>RoleAssignedEvent</c> raised
/// outside an aggregate) keep the same API.
/// </summary>
public sealed class MassTransitEventPublisher(
    IOutboxWriter outbox,
    ILogger<MassTransitEventPublisher> logger) : IEventPublisher
{
    public async Task PublishAsync<TEvent>(TEvent domainEvent, CancellationToken ct = default)
        where TEvent : DomainEvent
    {
        logger.LogDebug("Queuing domain event {EventType} ({EventId}) to outbox",
            typeof(TEvent).Name, domainEvent.EventId);
        await outbox.WriteAsync(domainEvent, ct);
    }
}
