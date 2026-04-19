using AuthService.Domain.Common;

namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Publishes all queued domain events on an entity, then clears them.
/// Presentation code depends on this interface, not the concrete dispatcher.
/// </summary>
public interface IDomainEventDispatcher
{
    Task DispatchAndClearAsync(Entity entity, CancellationToken ct = default);
}
