# Auth Service — Claude Code Guide
> .NET 10 · gRPC · Clean Architecture · Multi-Tenant · PostgreSQL · Redis · RabbitMQ

---

## Tech Stack

| Category      | Choice                                              |
|---------------|-----------------------------------------------------|
| Runtime       | .NET 10 / ASP.NET Core 10 / C# 14                  |
| Protocol      | gRPC + gRPC reflection                              |
| Gateway       | YARP (on ASP.NET Core)                              |
| Database      | PostgreSQL 18 + Npgsql (raw SQL — no EF Core)       |
| Migrations    | DbUp (versioned `.sql` scripts)                     |
| Cache         | Redis 7                                             |
| Messaging     | RabbitMQ → Kafka via MassTransit                    |
| Auth          | Custom JWT RS256 + OpenIddict (OIDC provider)       |
| MFA           | TOTP via OtpNet                                     |
| Observability | OpenTelemetry → Prometheus + Grafana                |
| Logging       | Serilog → Grafana Loki                              |
| Containers    | Docker + Kubernetes (local)                         |
| Architecture  | Clean Architecture                                  |
| Testing       | xUnit + TestContainers                              |

---

## Solution Structure (Clean Architecture)

```
src/
  AuthService.Domain/          # Entities, value objects, domain events
  AuthService.Application/     # Use cases, interfaces, DTOs, FluentValidation
  AuthService.Infrastructure/  # Npgsql repositories, Redis, RabbitMQ, DbUp migrations
  AuthService.Grpc/            # .proto files, gRPC server host
  AuthService.Gateway/         # ASP.NET Core + YARP reverse proxy
infra/
  init/                        # Docker init SQL (01-extensions, 02-schema)
  prometheus.yml
docker-compose.yml
```

---

## Build & Run

```bash
# Build
dotnet build src/AuthService/AuthService.csproj

# Run (requires infra to be up)
dotnet run --project src/AuthService/AuthService.csproj

# Start local infra
docker compose up -d

# Stop local infra
docker compose down
```

---

## Local Infrastructure Ports

| Service        | Port                        |
|----------------|-----------------------------|
| PostgreSQL     | 5433                        |
| Redis          | 6379                        |
| RabbitMQ       | 5672 / 15672 (management)   |
| Prometheus     | 9090                        |
| Grafana        | 3000                        |

---

## Multi-Tenancy

- Shared schema + PostgreSQL Row-Level Security (RLS)
- Every tenant-scoped table has `tenant_id UUID NOT NULL`
- Set tenant context per-request (transaction-scoped, not session-scoped):
  ```sql
  SET LOCAL app.current_tenant_id = '<uuid>';
  ```
- Tenant resolution order: subdomain → custom domain → `X-Tenant-ID` header
- System/global records use `tenant_id = NULL` (platform roles, permissions, signing keys)
- Unique constraints are per-tenant (email/username unique within a tenant, not globally)
- RLS bypass during DbUp migrations: connect as superuser, not the app role

---

## Database Rules

- **No EF Core** — raw SQL only via `NpgsqlConnection`
- Use `NpgsqlDataSource` for DI: `builder.Services.AddNpgsqlDataSource(connStr)`
- UUID PKs use `uuid_generate_v7()` (requires `pgcrypto` — see `infra/init/01-extensions.sql`)
- DbUp migration scripts: `AuthService.Infrastructure/Migrations/` as embedded resources, numbered `0001_`, `0002_`, etc.
- Tables with RLS: `users`, `roles`, `user_roles`, `refresh_tokens`, `oauth_clients`, `authorization_codes`, `user_consents`

---

## JWT & Tokens

- Access token: 15 min, RS256, claims include `tenant_id` + `user_id` + roles + permissions
- Refresh token: 7 days, stored hashed in PostgreSQL, rotated on use
- `tenant_id` claim is mandatory — always include it from day one
- Token blacklist in Redis with TTL matching token expiry (for logout/revocation)

---

## gRPC Protos

Proto files live in `AuthService.Grpc/Protos/`. Share compiled stubs via `Directory.Build.props` `<Protobuf>` item group.

Planned protos:
- `auth.proto` — Register, Login, RefreshToken, Logout, ValidateToken, GetUserInfo
- `tenant.proto` — CreateTenant, GetTenant, UpdateTenant, DeactivateTenant
- `roles.proto` — CreateRole, AssignRole, GetPermissions
- `mfa.proto` — EnableMfa, VerifyMfa, DisableMfa

---

## Configuration

- `appsettings.json` — base config
- `appsettings.Development.json` — dev overrides
- `appsettings.Local.json` — local secrets (gitignored, never commit)

---

## Coding Conventions

- Nullable reference types enabled — handle nulls explicitly
- Implicit usings enabled
- No EF Core anywhere — raw SQL only
- Password hashing: Argon2id via `Konscious.Security.Cryptography`
- Always include `tenant_id` as a span attribute / log property in OpenTelemetry
- Use `SET LOCAL` (not `SET`) for tenant context — avoids leaking across pooled connections

---

## Build Phases

| Phase | Focus                                     |
|-------|-------------------------------------------|
| 1     | Scaffolding, Docker/K8s, infra containers |
| 2     | Core auth gRPC RPCs, JWT, tenant middleware |
| 3     | RBAC, OAuth2/OIDC, MFA, invitations       |
| 4     | YARP gateway                              |
| 5     | OpenTelemetry, RabbitMQ events            |
| 6     | Testing, CI/CD, polyglot expansion        |

**Prioritize first:** tenant resolution middleware → RLS policies → JWT `tenant_id` claim → DbUp migrations → Register/Login RPCs → refresh token rotation.

**Defer:** full OIDC provider, MFA, tenant invitations, Kafka migration.
