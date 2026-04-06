# Auth Microservice — Build Plan
> .NET 10 · gRPC · Clean Architecture · Multi-Tenant · PostgreSQL · Redis · RabbitMQ

---

## Tech Stack

| Category      | Choice                                          |
|---------------|-------------------------------------------------|
| Runtime       | .NET 10 / ASP.NET Core 10 / C# 14              |
| Protocol      | gRPC + gRPC reflection                          |
| Gateway       | YARP (on ASP.NET Core)                          |
| Database      | PostgreSQL 18 + Npgsql (raw SQL — no EF Core)   |
| Migrations    | DbUp (versioned .sql scripts)                   |
| Cache         | Redis 7                                         |
| Messaging     | RabbitMQ → Kafka (via MassTransit)              |
| Auth          | Custom JWT RS256 + OpenIddict (OIDC provider)   |
| MFA           | TOTP via OtpNet                                 |
| Observability | OpenTelemetry → Prometheus + Grafana            |
| Logging       | Serilog → Grafana Loki                          |
| Containers    | Docker + Kubernetes (local)                     |
| Architecture  | Clean Architecture                              |
| Testing       | xUnit + TestContainers                          |

---

## Multi-Tenancy Strategy

**Approach: Shared schema + Row-Level Security (RLS)**

- Every tenant-scoped table carries a `tenant_id UUID NOT NULL` column
- PostgreSQL RLS policies enforce isolation at the DB layer (`app.current_tenant_id` session variable)
- The .NET service sets `SET LOCAL app.current_tenant_id = '<uuid>'` at the start of every request
- `signing_keys` and system-level roles/permissions are global (no `tenant_id`)
- Unique constraints are scoped per tenant (e.g. email is unique *within* a tenant, not globally)

**Tenant resolution order (pick one):**
1. Subdomain: `acme.auth.yourdomain.com` → resolve slug → load tenant
2. Custom domain: `auth.acme.com` → look up `tenants.custom_domain`
3. `X-Tenant-ID` header (for M2M / API clients)

---

## Phase 1 — Foundation & Project Scaffolding
**Week 1–2**

### Solution Structure (Clean Architecture)
- `AuthService.Domain` — Entities (`Tenant`, `User`, `Role`, `Permission`, `RefreshToken`), value objects, domain events
- `AuthService.Application` — Use cases/handlers, interfaces (`IUserRepository`, `ITokenService`, `ITenantRepository`), DTOs, validators (FluentValidation)
- `AuthService.Infrastructure` — Npgsql raw SQL repositories, Redis caching, RabbitMQ publishers, DbUp migrations
- `AuthService.Grpc` — gRPC service definitions (`.proto` files), gRPC server host
- `AuthService.Gateway` — ASP.NET Core + YARP reverse proxy

```
src/
  AuthService.Domain/
  AuthService.Application/
  AuthService.Infrastructure/
  AuthService.Grpc/
  AuthService.Gateway/
infra/
  init/                  # Docker init SQL: 01-extensions.sql, 02-schema.sql
  prometheus.yml
docker-compose.yml
```

### Local Kubernetes Setup
- Install Docker Desktop + enable Kubernetes (or use minikube/k3d)
- Create K8s manifests: `Deployment`, `Service`, `ConfigMap`, `Secret` for each component
- Docker Compose as fallback for quick iteration
- Tilt or Skaffold for hot-reload dev loop in K8s

### Infrastructure Containers
- PostgreSQL 18 — primary auth database (port **5433** to avoid local conflicts)
- Redis 7 — token blacklist, session cache, rate limiting
- RabbitMQ 3.13 — event bus (management UI on `:15672`)
- Jaeger or Grafana Tempo — trace collector
- Prometheus + Grafana — metrics & dashboards

---

## Phase 2 — Core Auth Service (gRPC)
**Week 3–5**

### Proto Definitions
- `auth.proto` — `Register`, `Login`, `RefreshToken`, `Logout`, `ValidateToken`, `GetUserInfo`
- `tenant.proto` — `CreateTenant`, `GetTenant`, `UpdateTenant`, `DeactivateTenant` *(NEW)*
- `roles.proto` — `CreateRole`, `AssignRole`, `GetPermissions`
- `mfa.proto` — `EnableMfa`, `VerifyMfa`, `DisableMfa`
- Enable gRPC reflection for debugging with `grpcurl` / Postman

### JWT Token Pipeline
- Access token (15 min) — RS256 signed, contains `tenant_id` + `user_id` + roles + permissions as claims
- Refresh token (7 days) — stored hashed in PostgreSQL, rotated on use
- `tenant_id` claim is mandatory; the gateway rejects tokens with a mismatched tenant
- Token blacklist in Redis — for logout & revocation with TTL matching token expiry
- Libraries: `Microsoft.AspNetCore.Authentication.JwtBearer`, `System.IdentityModel.Tokens.Jwt`

### Tenant Middleware (.NET)
```csharp
// gRPC interceptor — runs before every RPC
public class TenantResolutionInterceptor : Interceptor
{
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(...)
    {
        var tenantId = ResolveTenantFromMetadata(context); // header or JWT claim
        // Validate tenantId is a well-formed UUID before use
        if (!Guid.TryParse(tenantId, out var tenantGuid))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid tenant"));
        context.UserState["TenantId"] = tenantGuid;
        await using var conn = await _dataSource.OpenConnectionAsync();
        // Use SET LOCAL (transaction-scoped) — never SET (session-scoped), which leaks across pooled connections
        await conn.ExecuteAsync(
            "SET LOCAL app.current_tenant_id = @tenantId",
            new { tenantId = tenantGuid.ToString() });
        return await continuation(request, context);
    }
}
```

### Database Layer (Raw SQL + Npgsql)
- Raw SQL via `NpgsqlConnection` — no ORM, no EF Core, full control
- DbUp for versioned migrations — sequential `.sql` scripts in `AuthService.Infrastructure/Migrations/` as embedded resources
- **15 tables**: `tenants`, `users`, `roles`, `permissions`, `user_roles`, `role_permissions`, `refresh_tokens`, `mfa_secrets`, `mfa_recovery_codes`, `oauth_clients`, `authorization_codes`, `user_consents`, `verification_tokens`, `tenant_invitations`, `audit_log`, `signing_keys`
- UUID PKs use `uuid_generate_v7()` — requires `pgcrypto` extension (enabled in `infra/init/01-extensions.sql`)
- Tables with RLS enabled: `users`, `roles`, `user_roles`, `refresh_tokens`, `oauth_clients`, `authorization_codes`, `user_consents`
- RLS bypass during migrations: connect as superuser, not the app role
- `NpgsqlDataSource` for .NET 10 DI-friendly async connection pooling

### Password & Security
- Argon2id via `Konscious.Security.Cryptography` (preferred over BCrypt for new builds)
- Account lockout threshold configurable **per tenant** via `tenants.password_policy` JSONB
- Rate limiting on login/register endpoints (Redis sliding window, keyed by `tenant_id:ip`)

---

## Phase 3 — RBAC & OAuth2/OIDC
**Week 6–8**

### RBAC Implementation
- System roles (`tenant_id IS NULL`): `SuperAdmin`, `Admin`, `TenantAdmin`, `User`
- Custom roles scoped per tenant — tenants can create their own roles
- Permission cache in Redis — key: `permissions:{tenant_id}:{user_id}` — invalidate via RabbitMQ event
- gRPC interceptor validates permissions per-method, extracting `tenant_id` from JWT

### OAuth2 / OIDC Provider (Custom — No Keycloak/Duende)
- Each tenant registers its own OAuth clients (`oauth_clients.tenant_id`)
- Authorization Code flow with PKCE
- Endpoints: `/authorize`, `/token`, `/userinfo`, `/.well-known/openid-configuration`, `/jwks`
- Tenant resolved from subdomain or `client_id` prefix at the `/authorize` endpoint
- ID Token contains `tenant_id` claim
- Library: OpenIddict (MIT licensed) or build from scratch

### 2FA / MFA
- TOTP-based (Google Authenticator / Authy compatible)
- MFA can be enforced globally per tenant via `tenants.mfa_required = TRUE`
- Backup/recovery codes (hashed, one-time use)
- Library: OtpNet

### Tenant Invitations
- `POST /invite` — generates signed token, emails invite link
- Accepting the invite creates the user and assigns the pre-configured role
- Tokens expire (default 48 h), stored hashed in `tenant_invitations`

---

## Phase 4 — API Gateway (YARP)
**Week 9–10**

### Why YARP?
- Built by Microsoft, runs inside ASP.NET Core — stays in the .NET ecosystem
- NuGet: `Yarp.ReverseProxy`
- Config-driven routing via `appsettings.json` or code
- Handles polyglot services (Go, Node, Rust) identically

### Gateway Responsibilities
- Tenant resolution at the edge — injects `X-Tenant-ID` header for downstream services
- JWT validation middleware — validates access tokens before forwarding
- Rate limiting (per-client, per-IP, per-tenant) via built-in .NET rate limiter
- Request/response transformation & header enrichment
- gRPC-JSON transcoding — expose gRPC services as REST to external consumers
- Health check aggregation (`/health`) for all downstream services

---

## Phase 5 — Observability & Events
**Week 11–12**

### OpenTelemetry Stack
- Traces → OpenTelemetry Collector → Grafana Tempo (or Jaeger)
- Metrics → Prometheus scraping `/metrics` endpoint → Grafana dashboards
- Logs → Serilog with structured logging → Grafana Loki (or Seq)
- NuGet: `OpenTelemetry.Extensions.Hosting`, `OpenTelemetry.Instrumentation.AspNetCore`, `OpenTelemetry.Exporter.Prometheus`
- Instrument gRPC calls, Npgsql queries, Redis commands, RabbitMQ publishes
- **Always include `tenant_id` as a span attribute / log property**

### RabbitMQ Event Bus (MassTransit)
- Events: `TenantCreated`, `UserRegistered`, `UserLoggedIn`, `PasswordChanged`, `RoleAssigned`, `MfaEnabled`, `AccountLocked`
- All events carry `TenantId` in the message envelope
- Dead letter queue for failed messages
- MassTransit makes Kafka swap easy when event volume justifies it

### Grafana Dashboards
- Auth service health: request rate, error rate, latency P50/P95/P99
- Business metrics: registrations/day, login success/failure ratio, MFA adoption rate
- **Tenant-level dashboards**: active tenants, per-tenant login volume, per-tenant failures
- Infrastructure: Redis hit rate, RabbitMQ queue depth, PostgreSQL connection pool

---

## Phase 6 — Polish & Polyglot Prep
**Week 13+**

### Testing
- Unit tests: xUnit + Moq/NSubstitute for domain & application layers
- Integration tests: TestContainers (spin up real PostgreSQL/Redis/RabbitMQ in Docker)
- gRPC integration tests: `Grpc.Net.Client` against a `TestServer`
- **Multi-tenant test fixtures**: create two tenants and assert data isolation between them

### CI/CD
- GitHub Actions: `build → test → Docker image → push to registry`
- Helm charts for K8s deployment (or Kustomize)
- Automated DB migrations on deploy via DbUp

### Polyglot Expansion Path
- Next service in Go, Rust, or Node — consuming auth events via RabbitMQ
- Share `.proto` files via a shared Git repo or Buf Schema Registry
- Each new service resolves tenant from the JWT `tenant_id` claim or `X-Tenant-ID` header
- YARP routes each new service identically

---

## Schema Changes vs. Single-Tenant Version

| Table                  | Change                                                                |
|------------------------|-----------------------------------------------------------------------|
| `tenants`              | **NEW** — root of the multi-tenant model                             |
| `users`                | Added `tenant_id`; email/username unique **per tenant**              |
| `roles`                | Added `tenant_id` (NULL = system role)                               |
| `permissions`          | Added `tenant_id` (NULL = platform permission)                       |
| `user_roles`           | Added `tenant_id` for RLS                                            |
| `refresh_tokens`       | Added `tenant_id`                                                    |
| `oauth_clients`        | Added `tenant_id`; each tenant manages its own clients               |
| `authorization_codes`  | Added `tenant_id`                                                    |
| `user_consents`        | Added `tenant_id`; unique constraint scoped per tenant               |
| `audit_log`            | Added `tenant_id` (NULL = platform-level action)                     |
| `tenant_invitations`   | **NEW** — invite users to a tenant                                   |
| `signing_keys`         | **Unchanged** — global, shared across all tenants                    |
| `mfa_secrets`          | **Unchanged** — implicitly tenant-scoped via `user_id`               |
| `mfa_recovery_codes`   | **Unchanged** — implicitly tenant-scoped via `user_id`               |
| `verification_tokens`  | **Unchanged** — implicitly tenant-scoped via `user_id`               |

All tenant-scoped tables have PostgreSQL **Row-Level Security** policies enabled.

---

## What to Prioritize First

### Immediate (do before writing any feature code)
1. **`tenants` table and tenant resolution middleware** — every other table depends on it. Wire up the gRPC interceptor that sets `app.current_tenant_id` per request. Without this, you'll constantly retrofit tenant context later.
2. **RLS policies** — enable them in the initial DbUp migration, not as an afterthought. Adding RLS to a table with existing data is risky and easy to get wrong.
3. **JWT `tenant_id` claim** — bake this into your token generation from day one. Retrofitting a new claim breaks all existing tokens.

### Week 1–5 Core Loop
4. **Foundation scaffolding + Docker Compose** — get Postgres + Redis + RabbitMQ running locally before any .NET code.
5. **DbUp migrations** — run schema above as migration `0001_initial.sql`. All future work depends on stable tables.
6. **Register + Login gRPC RPCs** — the smallest slice that proves tenant isolation works end-to-end.
7. **Refresh token rotation** — do this early; it's easy to get wrong and painful to fix later.

### Defer Until Phase 3+
- Full OIDC provider implementation (complex, not needed for internal gRPC-only services)
- MFA (correct but non-blocking for early integration)
- Tenant invitations (nice-to-have until you have more than one real tenant)
- Kafka migration (RabbitMQ is fine until you have measurable volume)

---

## Notes for Claude Code

- Set `app.current_tenant_id` using `SET LOCAL` (transaction-scoped) not `SET` (session-scoped), so Npgsql connection pooling doesn't leak tenant context across requests.
- Validate `tenant_id` is a well-formed UUID before interpolating into any SQL — never use raw string interpolation.
- Use `NpgsqlDataSource` with `.NET 10` DI: `builder.Services.AddNpgsqlDataSource(connStr)`.
- UUID PKs use `uuid_generate_v7()` — enable the `pgcrypto` extension in `infra/init/01-extensions.sql` before running migrations.
- PostgreSQL runs on port **5433** locally (non-default, avoids conflicts with any local install).
- DbUp migration scripts go in `AuthService.Infrastructure/Migrations/` as embedded resources, numbered `0001_`, `0002_`, etc.
- For RLS bypass during migrations, connect as the superuser role, not the app role.
- Proto files live in `AuthService.Grpc/Protos/` and should be shared via a `Directory.Build.props` `<Protobuf>` item group so all projects reference the same compiled stubs.
- Local secrets go in `appsettings.Local.json` (gitignored — never commit).
