using System.Text.Json;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Common;
using AuthService.Infrastructure.Persistence;
using NpgsqlTypes;

namespace AuthService.Infrastructure.Messaging;

/// <summary>
/// Persists a domain event to <c>outbox_events</c> through the shared unit-of-work
/// session. When a UoW transaction is active, the outbox row commits atomically with the
/// business state — the "true" transactional outbox. When no UoW is active, the write
/// still succeeds in its own short-lived transaction; the only failure window left is
/// a crash between the business commit and the outbox commit, which is a narrow race.
/// </summary>
public sealed class OutboxWriter(IDbSessionProvider sessions) : IOutboxWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy        = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
    };

    public async Task WriteAsync(DomainEvent domainEvent, CancellationToken ct = default)
    {
        var eventType = domainEvent.GetType().AssemblyQualifiedName
            ?? throw new InvalidOperationException("Event type has no assembly-qualified name.");
        var payload   = JsonSerializer.Serialize(domainEvent, domainEvent.GetType(), JsonOptions);
        var tenantId  = (domainEvent as ITenantScopedEvent)?.TenantId;

        await using var session = await sessions.GetSessionAsync(ct: ct);
        await using var cmd = session.Connection.CreateCommand();
        cmd.Transaction = session.Transaction;
        cmd.CommandText = """
            INSERT INTO outbox_events (id, event_type, payload, tenant_id, created_at)
            VALUES ($1, $2, $3, $4, $5)
            """;
        cmd.Parameters.AddWithValue(domainEvent.EventId);
        cmd.Parameters.AddWithValue(eventType);
        cmd.Parameters.Add(new Npgsql.NpgsqlParameter { NpgsqlDbType = NpgsqlDbType.Jsonb, Value = payload });
        cmd.Parameters.AddWithValue(tenantId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue(domainEvent.OccurredAt);

        await cmd.ExecuteNonQueryAsync(ct);
        await session.CommitAsync(ct);
    }
}
