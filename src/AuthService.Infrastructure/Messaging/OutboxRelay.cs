using System.Text.Json;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Common;
using MassTransit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace AuthService.Infrastructure.Messaging;

/// <summary>
/// Polls <c>outbox_events</c> for unpublished rows, publishes each to MassTransit, and
/// marks the row published. Rows that fail get an incremented <c>attempt_count</c> and a
/// recorded <c>last_error</c>; they stay eligible until a later poll succeeds.
///
/// Selection uses <c>FOR UPDATE SKIP LOCKED</c> so multiple instances of the auth service
/// can run the relay concurrently without double-publishing.
/// </summary>
public sealed class OutboxRelay(
    NpgsqlDataSource dataSource,
    IServiceScopeFactory scopeFactory,
    ILogger<OutboxRelay> logger) : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(2);
    private const int BatchSize = 50;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy        = JsonNamingPolicy.SnakeCaseLower,
        PropertyNameCaseInsensitive = true,
    };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Outbox relay started");
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var processed = await ProcessBatchAsync(stoppingToken);
                if (processed == 0)
                    await Task.Delay(PollInterval, stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                logger.LogError(ex, "Outbox relay batch failed — backing off");
                try { await Task.Delay(PollInterval, stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }
    }

    private async Task<int> ProcessBatchAsync(CancellationToken ct)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx   = await conn.BeginTransactionAsync(ct);

        var pending = await FetchPendingAsync(conn, tx, ct);
        if (pending.Count == 0)
        {
            await tx.CommitAsync(ct);
            return 0;
        }

        using var scope = scopeFactory.CreateScope();
        var publishEndpoint = scope.ServiceProvider.GetRequiredService<IPublishEndpoint>();

        foreach (var row in pending)
        {
            try
            {
                var eventType = Type.GetType(row.EventType, throwOnError: false);
                if (eventType is null)
                {
                    await MarkFailedAsync(conn, tx, row.Id, $"Unknown event type '{row.EventType}'", ct);
                    continue;
                }

                var domainEvent = (DomainEvent?)JsonSerializer.Deserialize(row.Payload, eventType, JsonOptions);
                if (domainEvent is null)
                {
                    await MarkFailedAsync(conn, tx, row.Id, "Deserialized event was null", ct);
                    continue;
                }

                await publishEndpoint.Publish(domainEvent, eventType, ct);
                await MarkPublishedAsync(conn, tx, row.Id, ct);

                logger.LogDebug("Outbox published {EventType} ({EventId})", eventType.Name, row.Id);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Outbox publish failed for event {EventId} ({EventType})", row.Id, row.EventType);
                await MarkFailedAsync(conn, tx, row.Id, ex.Message, ct);
            }
        }

        await tx.CommitAsync(ct);
        return pending.Count;
    }

    private static async Task<List<OutboxRow>> FetchPendingAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            SELECT id, event_type, payload::text
            FROM outbox_events
            WHERE published_at IS NULL
            ORDER BY created_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
            """;
        cmd.Parameters.AddWithValue(BatchSize);

        var rows = new List<OutboxRow>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new OutboxRow(
                Id:        reader.GetGuid(0),
                EventType: reader.GetString(1),
                Payload:   reader.GetString(2)));
        }
        return rows;
    }

    private static async Task MarkPublishedAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, Guid id, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE outbox_events
               SET published_at  = now(),
                   attempt_count = attempt_count + 1,
                   last_error    = NULL
             WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(id);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task MarkFailedAsync(
        NpgsqlConnection conn, NpgsqlTransaction tx, Guid id, string error, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            UPDATE outbox_events
               SET attempt_count = attempt_count + 1,
                   last_error    = $2
             WHERE id = $1
            """;
        cmd.Parameters.AddWithValue(id);
        cmd.Parameters.AddWithValue(error);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private sealed record OutboxRow(Guid Id, string EventType, string Payload);
}
