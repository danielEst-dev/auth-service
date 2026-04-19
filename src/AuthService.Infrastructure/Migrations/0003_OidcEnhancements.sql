-- 0003_OidcEnhancements.sql
-- Adds require_consent column, nonce column, and fixes oauth_clients RLS
-- for cross-tenant client_id lookups at the /oauth/authorize endpoint.

-- 1. Add require_consent flag to oauth_clients
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS require_consent BOOLEAN NOT NULL DEFAULT FALSE;

-- 2. Add nonce column to authorization_codes (echoed back in ID token)
ALTER TABLE authorization_codes
    ADD COLUMN IF NOT EXISTS nonce VARCHAR(512);

-- 3. Fix oauth_clients RLS to allow cross-tenant client_id lookup.
--    The /oauth/authorize endpoint must resolve the client before tenant context
--    is established, so the policy must permit reads when no tenant is set.
DROP POLICY IF EXISTS oauth_clients_tenant_isolation ON oauth_clients;
CREATE POLICY oauth_clients_tenant_isolation ON oauth_clients
    USING (
        current_setting('app.current_tenant_id', true) = ''
        OR tenant_id = current_setting('app.current_tenant_id', true)::UUID
    );
