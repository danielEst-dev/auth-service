-- ============================================================================
-- AUTH MICROSERVICE - PostgreSQL Database Schema (Multi-Tenant Edition)
-- .NET 10 / gRPC / Clean Architecture
-- Strategy: Shared schema, tenant_id on every tenant-scoped table + RLS
-- ============================================================================
-- Migration tool: DbUp or FluentMigrator (no EF Core)
-- Driver: Npgsql (raw SQL via NpgsqlConnection)
-- ============================================================================

-- ============================================================================
-- TENANTS  (NEW - root of the multi-tenant tree)
-- ============================================================================

CREATE TABLE tenants (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    slug                VARCHAR(100) NOT NULL,       -- URL-safe identifier: 'acme-corp'
    name                VARCHAR(200) NOT NULL,
    plan                VARCHAR(50) NOT NULL DEFAULT 'free',  -- 'free', 'pro', 'enterprise'

    -- Isolation config
    custom_domain       VARCHAR(255),                -- e.g. auth.acme.com
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    is_system_tenant    BOOLEAN NOT NULL DEFAULT FALSE, -- The root/platform tenant

    -- Security settings (per-tenant overrides)
    password_policy     JSONB NOT NULL DEFAULT '{
        "min_length": 8,
        "require_uppercase": true,
        "require_digit": true,
        "require_symbol": false,
        "max_failed_attempts": 5,
        "lockout_duration_minutes": 15
    }',
    mfa_required        BOOLEAN NOT NULL DEFAULT FALSE,
    session_lifetime_minutes INT NOT NULL DEFAULT 60,
    allowed_sso_providers JSONB NOT NULL DEFAULT '[]', -- ['google', 'github', 'saml']

    -- Token lifetime overrides (NULL = use global default)
    access_token_lifetime_seconds  INT,
    refresh_token_lifetime_seconds INT,

    -- Branding
    logo_url            TEXT,
    primary_color       VARCHAR(7),                 -- '#22d3ee'

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_tenants_slug UNIQUE (slug),
    CONSTRAINT uq_tenants_custom_domain UNIQUE (custom_domain)
);

CREATE INDEX idx_tenants_slug ON tenants (slug);
CREATE INDEX idx_tenants_is_active ON tenants (is_active) WHERE is_active = TRUE;

-- ============================================================================
-- CORE IDENTITY  (tenant-scoped)
-- ============================================================================

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,  -- NEW

    email               VARCHAR(255) NOT NULL,
    normalized_email    VARCHAR(255) NOT NULL,
    username            VARCHAR(100) NOT NULL,
    normalized_username VARCHAR(100) NOT NULL,
    password_hash       TEXT,                        -- NULL for pure SSO users

    -- Profile
    first_name          VARCHAR(100),
    last_name           VARCHAR(100),
    phone_number        VARCHAR(20),
    avatar_url          TEXT,

    -- Account state
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    is_email_confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
    is_phone_confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
    is_locked_out       BOOLEAN NOT NULL DEFAULT FALSE,
    lockout_end_utc     TIMESTAMPTZ,
    failed_login_count  INT NOT NULL DEFAULT 0,

    -- MFA
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,

    -- External identity (SSO / OAuth login via external IdP)
    external_provider   VARCHAR(50),
    external_provider_id VARCHAR(255),

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ,

    -- Scoped uniqueness: email/username unique per tenant, not globally
    CONSTRAINT uq_users_email_per_tenant    UNIQUE (tenant_id, normalized_email),
    CONSTRAINT uq_users_username_per_tenant UNIQUE (tenant_id, normalized_username),
    CONSTRAINT uq_users_external_provider   UNIQUE (tenant_id, external_provider, external_provider_id)
);

CREATE INDEX idx_users_tenant_email    ON users (tenant_id, normalized_email);
CREATE INDEX idx_users_tenant_username ON users (tenant_id, normalized_username);
CREATE INDEX idx_users_is_active       ON users (tenant_id, is_active) WHERE is_active = TRUE;

-- Row-Level Security: enforce tenant isolation at DB layer
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_isolation ON users
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- ============================================================================
-- RBAC - ROLES & PERMISSIONS  (tenant-scoped + system-level)
-- ============================================================================

CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = system/global role
    name            VARCHAR(100) NOT NULL,
    normalized_name VARCHAR(100) NOT NULL,
    description     TEXT,
    is_system_role  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Name is unique within a tenant (or globally for system roles)
    CONSTRAINT uq_roles_name_per_tenant UNIQUE (tenant_id, normalized_name)
);

CREATE INDEX idx_roles_tenant_id ON roles (tenant_id);

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY roles_tenant_isolation ON roles
    USING (tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE TABLE permissions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = platform permission
    name            VARCHAR(200) NOT NULL,
    description     TEXT,
    resource        VARCHAR(100) NOT NULL,
    action          VARCHAR(50) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_permissions_resource_action_tenant UNIQUE (tenant_id, resource, action)
);

CREATE INDEX idx_permissions_tenant_id ON permissions (tenant_id);

-- Many-to-many: users <-> roles (always tenant-scoped via user)
CREATE TABLE user_roles (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,  -- Denormalized for RLS
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by     UUID REFERENCES users(id),

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_role_id    ON user_roles (role_id);
CREATE INDEX idx_user_roles_tenant_id  ON user_roles (tenant_id);

ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_roles_tenant_isolation ON user_roles
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Many-to-many: roles <-> permissions
CREATE TABLE role_permissions (
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id   UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_permission_id ON role_permissions (permission_id);

-- ============================================================================
-- AUTHENTICATION TOKENS  (tenant-scoped)
-- ============================================================================

CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,  -- NEW
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(512) NOT NULL,
    jti             VARCHAR(100) NOT NULL,

    -- Device/session tracking
    device_info     VARCHAR(500),
    ip_address      INET,

    -- Lifecycle
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by_id  UUID REFERENCES refresh_tokens(id),

    CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT uq_refresh_tokens_jti        UNIQUE (jti)
);

CREATE INDEX idx_refresh_tokens_user_id    ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_tenant_id  ON refresh_tokens (tenant_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at)
    WHERE revoked_at IS NULL;

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY refresh_tokens_tenant_isolation ON refresh_tokens
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- ============================================================================
-- MFA / TWO-FACTOR AUTHENTICATION  (tenant-scoped via user)
-- ============================================================================

CREATE TABLE mfa_secrets (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret_encrypted TEXT NOT NULL,
    method           VARCHAR(20) NOT NULL DEFAULT 'totp',
    is_confirmed     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_mfa_secrets_user_method UNIQUE (user_id, method)
);

CREATE TABLE mfa_recovery_codes (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   VARCHAR(512) NOT NULL,
    is_used     BOOLEAN NOT NULL DEFAULT FALSE,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_recovery_codes_user_id ON mfa_recovery_codes (user_id)
    WHERE is_used = FALSE;

-- ============================================================================
-- OAUTH2 / OIDC PROVIDER  (tenant-scoped — each tenant registers its own clients)
-- ============================================================================

CREATE TABLE oauth_clients (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,  -- NEW
    client_id       VARCHAR(255) NOT NULL,
    client_secret_hash VARCHAR(512),
    client_name     VARCHAR(200) NOT NULL,
    client_type     VARCHAR(20) NOT NULL DEFAULT 'confidential',

    redirect_uris               JSONB NOT NULL DEFAULT '[]',
    post_logout_redirect_uris   JSONB NOT NULL DEFAULT '[]',
    allowed_scopes              JSONB NOT NULL DEFAULT '["openid", "profile", "email"]',
    allowed_grant_types         JSONB NOT NULL DEFAULT '["authorization_code"]',

    require_pkce    BOOLEAN NOT NULL DEFAULT TRUE,

    -- NULL = inherit from tenant settings
    access_token_lifetime  INT,
    refresh_token_lifetime INT,

    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- client_id is unique globally (it appears in JWTs and must be unambiguous)
    CONSTRAINT uq_oauth_clients_client_id UNIQUE (client_id)
);

CREATE INDEX idx_oauth_clients_tenant_id ON oauth_clients (tenant_id);

ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY oauth_clients_tenant_isolation ON oauth_clients
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE TABLE authorization_codes (
    id                      UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,  -- NEW
    code_hash               VARCHAR(512) NOT NULL,
    client_id               UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri            TEXT NOT NULL,
    scopes                  JSONB NOT NULL DEFAULT '[]',

    -- PKCE
    code_challenge          VARCHAR(512),
    code_challenge_method   VARCHAR(10) DEFAULT 'S256',

    issued_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ NOT NULL,
    is_redeemed             BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT uq_authorization_codes_hash UNIQUE (code_hash)
);

CREATE INDEX idx_auth_codes_expires ON authorization_codes (expires_at)
    WHERE is_redeemed = FALSE;

CREATE TABLE user_consents (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,  -- NEW
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes      JSONB NOT NULL DEFAULT '[]',
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,

    CONSTRAINT uq_user_consents UNIQUE (tenant_id, user_id, client_id)
);

-- ============================================================================
-- EMAIL CONFIRMATION & PASSWORD RESET  (tenant-scoped via user)
-- ============================================================================

CREATE TABLE verification_tokens (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(512) NOT NULL,
    purpose     VARCHAR(50) NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    is_used     BOOLEAN NOT NULL DEFAULT FALSE,
    used_at     TIMESTAMPTZ,

    CONSTRAINT uq_verification_tokens_hash UNIQUE (token_hash)
);

CREATE INDEX idx_verification_tokens_user ON verification_tokens (user_id, purpose)
    WHERE is_used = FALSE;

-- ============================================================================
-- TENANT INVITATIONS  (NEW — invite users to a tenant)
-- ============================================================================

CREATE TABLE tenant_invitations (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    token_hash      VARCHAR(512) NOT NULL,
    role_id         UUID REFERENCES roles(id),       -- Pre-assign a role on accept
    invited_by      UUID REFERENCES users(id),
    accepted_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_tenant_invitations_token UNIQUE (token_hash),
    CONSTRAINT uq_tenant_invitations_email UNIQUE (tenant_id, email)   -- One pending invite per email per tenant
);

CREATE INDEX idx_tenant_invitations_tenant ON tenant_invitations (tenant_id);

-- ============================================================================
-- AUDIT LOG  (tenant-scoped, partition by time for scale)
-- ============================================================================

CREATE TABLE audit_log (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID REFERENCES tenants(id) ON DELETE SET NULL,  -- NULL = platform-level action
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id   UUID,
    ip_address  INET,
    user_agent  TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_tenant_id  ON audit_log (tenant_id);
CREATE INDEX idx_audit_log_user_id    ON audit_log (user_id);
CREATE INDEX idx_audit_log_action     ON audit_log (action);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX idx_audit_log_entity     ON audit_log (entity_type, entity_id);

-- ============================================================================
-- SIGNING KEYS  (GLOBAL — shared across all tenants, rotated platform-wide)
-- Note: For enterprise tenant isolation, you can add an optional tenant_id
--       to support per-tenant key pairs, but start global.
-- ============================================================================

CREATE TABLE signing_keys (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    kid                   VARCHAR(100) NOT NULL,
    algorithm             VARCHAR(10) NOT NULL DEFAULT 'RS256',
    private_key_encrypted TEXT NOT NULL,
    public_key_pem        TEXT NOT NULL,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    activated_at          TIMESTAMPTZ,
    expires_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_signing_keys_kid UNIQUE (kid)
);

-- ============================================================================
-- HELPER: RLS bypass for service role (your .NET service connects as this role)
-- ============================================================================
-- In production, create a dedicated DB role for the application:
--   CREATE ROLE auth_service LOGIN PASSWORD '...';
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auth_service;
-- Set tenant context per-request:
--   SET LOCAL app.current_tenant_id = '<uuid>';
-- Or use a connection-level setting via Npgsql:
--   await conn.ExecuteAsync("SET app.current_tenant_id = @tid", new { tid = tenantId });

-- ============================================================================
-- HELPER FUNCTION: Auto-update updated_at
-- ============================================================================

CREATE OR REPLACE FUNCTION fn_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

CREATE TRIGGER trg_roles_updated_at
    BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

CREATE TRIGGER trg_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION fn_set_updated_at();

-- ============================================================================
-- SEED DATA
-- ============================================================================

-- System tenant (your own platform)
INSERT INTO tenants (id, slug, name, is_system_tenant, plan) VALUES
    ('00000000-0000-0000-0000-000000000001', 'system', 'Platform Root', TRUE, 'enterprise');

-- System roles (tenant_id NULL = available to all tenants)
INSERT INTO roles (id, tenant_id, name, normalized_name, description, is_system_role) VALUES
    (uuid_generate_v7(), NULL, 'SuperAdmin', 'SUPERADMIN', 'Full system access',      TRUE),
    (uuid_generate_v7(), NULL, 'Admin',      'ADMIN',      'Administrative access',   TRUE),
    (uuid_generate_v7(), NULL, 'User',       'USER',       'Standard user access',    TRUE),
    (uuid_generate_v7(), NULL, 'TenantAdmin','TENANTADMIN','Manage a single tenant',  TRUE);

-- Platform permissions
INSERT INTO permissions (id, tenant_id, name, description, resource, action) VALUES
    (uuid_generate_v7(), NULL, 'user:read',        'View user profiles',            'user',       'read'),
    (uuid_generate_v7(), NULL, 'user:write',       'Create and update users',       'user',       'write'),
    (uuid_generate_v7(), NULL, 'user:delete',      'Delete user accounts',          'user',       'delete'),
    (uuid_generate_v7(), NULL, 'role:read',        'View roles',                    'role',       'read'),
    (uuid_generate_v7(), NULL, 'role:write',       'Create and update roles',       'role',       'write'),
    (uuid_generate_v7(), NULL, 'role:assign',      'Assign roles to users',         'role',       'assign'),
    (uuid_generate_v7(), NULL, 'permission:read',  'View permissions',              'permission', 'read'),
    (uuid_generate_v7(), NULL, 'permission:write', 'Create and update permissions', 'permission', 'write'),
    (uuid_generate_v7(), NULL, 'client:read',      'View OAuth clients',            'client',     'read'),
    (uuid_generate_v7(), NULL, 'client:write',     'Manage OAuth clients',          'client',     'write'),
    (uuid_generate_v7(), NULL, 'audit:read',       'View audit logs',               'audit',      'read'),
    (uuid_generate_v7(), NULL, 'tenant:read',      'View tenants',                  'tenant',     'read'),   -- NEW
    (uuid_generate_v7(), NULL, 'tenant:write',     'Create and update tenants',     'tenant',     'write'),  -- NEW
    (uuid_generate_v7(), NULL, 'tenant:delete',    'Delete tenants',                'tenant',     'delete'); -- NEW