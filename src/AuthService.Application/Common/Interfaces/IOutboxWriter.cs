using AuthService.Domain.Common;

namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Durably enqueues a domain event for later publish by the outbox relay.
/// The write is the authoritative signal that the event "happened" — the relay
/// guarantees at-least-once delivery to the transport (RabbitMQ) independent of
/// broker availability at dispatch time.
/// </summary>
public interface IOutboxWriter
{
    Task WriteAsync(DomainEvent domainEvent, CancellationToken ct = default);
}
