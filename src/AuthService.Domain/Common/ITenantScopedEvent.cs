namespace AuthService.Domain.Common;

/// <summary>
/// Marker for domain events that belong to a specific tenant. The outbox uses this to
/// populate <c>outbox_events.tenant_id</c> at write time — downstream consumers can
/// filter by tenant without parsing the payload. Compile-checked so a new event can't
/// be added without consciously deciding whether it's tenant-scoped.
/// </summary>
public interface ITenantScopedEvent
{
    Guid TenantId { get; }
}
