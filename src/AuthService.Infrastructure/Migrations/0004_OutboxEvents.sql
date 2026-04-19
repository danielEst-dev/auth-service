-- 0004_OutboxEvents.sql
-- Transactional outbox for domain events.
-- Dispatcher INSERTs rows here; the background relay publishes to RabbitMQ and
-- marks rows as published. This protects against broker outages and restart
-- races between a DB commit and a publish attempt.

CREATE TABLE IF NOT EXISTS outbox_events (
    id              UUID        PRIMARY KEY,
    event_type      TEXT        NOT NULL,
    payload         JSONB       NOT NULL,
    tenant_id       UUID        NULL,           -- denormalized from payload for filtering
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ NULL,
    attempt_count   INT         NOT NULL DEFAULT 0,
    last_error      TEXT        NULL
);

-- Hot index: the relay's poll query is "WHERE published_at IS NULL ORDER BY created_at".
-- A partial index keeps it compact — once a row is published it falls out.
CREATE INDEX IF NOT EXISTS ix_outbox_events_pending
    ON outbox_events (created_at)
    WHERE published_at IS NULL;

-- No RLS on the outbox: the relay runs as a background service without a user
-- tenant context, and the tenant_id is embedded in the event payload for downstream
-- consumers that care.
