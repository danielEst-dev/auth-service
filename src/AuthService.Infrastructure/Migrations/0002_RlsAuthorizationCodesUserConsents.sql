-- ============================================================================
-- Migration 0002: Add RLS policies for authorization_codes and user_consents
-- These tables were created in 0001 but their RLS policies were omitted.
-- ============================================================================

ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY authorization_codes_tenant_isolation ON authorization_codes
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

ALTER TABLE user_consents ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_consents_tenant_isolation ON user_consents
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
