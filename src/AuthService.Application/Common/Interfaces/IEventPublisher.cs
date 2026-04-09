using AuthService.Domain.Common;

namespace AuthService.Application.Common.Interfaces;

public interface IEventPublisher
{
    Task PublishAsync<TEvent>(TEvent domainEvent, CancellationToken ct = default)
        where TEvent : DomainEvent;
}
