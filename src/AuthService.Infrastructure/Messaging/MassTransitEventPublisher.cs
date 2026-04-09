using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Common;
using MassTransit;
using Microsoft.Extensions.Logging;

namespace AuthService.Infrastructure.Messaging;

public sealed class MassTransitEventPublisher(
    IPublishEndpoint publishEndpoint,
    ILogger<MassTransitEventPublisher> logger) : IEventPublisher
{
    public async Task PublishAsync<TEvent>(TEvent domainEvent, CancellationToken ct = default)
        where TEvent : DomainEvent
    {
        logger.LogInformation(
            "Publishing domain event {EventType} ({EventId})",
            typeof(TEvent).Name, domainEvent.EventId);

        await publishEndpoint.Publish(domainEvent, ct);
    }
}
