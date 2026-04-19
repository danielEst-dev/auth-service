# Plan: Complete Phase 2 & 3 Implementation

## Context

The auth-service has Phase 1 fully complete and Phase 2 at ~90%. Phase 3 RBAC foundations exist (roles, permissions, assignment) but the major features — MFA, OAuth2/OIDC, tenant invitations, permission caching/interceptor — are missing. This plan completes Phase 2's `mfa.proto` gap and all remaining Phase 3 items in dependency order.

---

## Implementation Steps (ordered by dependencies)

### Step 1: MFA Domain Entities & Repository

New domain entities for MFA and verification tokens, plus their repositories.

**Files to create:**
- `src/AuthService.Domain/Entities/MfaSecret.cs` — sealed class extends Entity: UserId, SecretEncrypted, Method (default "totp"), IsConfirmed, CreatedAt. Factory: `Create()`, `Confirm()`, `Reconstitute()`.
- `src/AuthService.Domain/Entities/MfaRecoveryCode.cs` — sealed class extends Entity: UserId, CodeHash, IsUsed, UsedAt, CreatedAt. Factory: `Create()`, `MarkUsed()`, `Reconstitute()`.
- `src/AuthService.Domain/Entities/VerificationToken.cs` — sealed class extends Entity: UserId, TokenHash, Purpose, IssuedAt, ExpiresAt, IsUsed, UsedAt. Factory: `Create()`, `MarkUsed()`, `Reconstitute()`. Computed: `IsExpired`, `IsValid`.
- `src/AuthService.Domain/Events/MfaEnabledEvent.cs` — sealed record: `(Guid UserId, Guid TenantId, string Method) : DomainEvent`
- `src/AuthService.Application/Common/Interfaces/IMfaRepository.cs` — GetSecretByUserIdAsync(userId), CreateSecretAsync(secret), UpdateSecretAsync(secret), DeleteSecretAsync(userId), GetRecoveryCodesAsync(userId), CreateRecoveryCodesAsync(codes), MarkRecoveryCodeUsedAsync(codeId), GetUnusedRecoveryCodeByHashAsync(userId, codeHash)
- `src/AuthService.Application/Common/Interfaces/IVerificationTokenRepository.cs` — GetByTokenHashAsync(tokenHash), CreateAsync(token), MarkUsedAsync(tokenId)

**Files to modify:**
- `src/AuthService.Domain/Entities/User.cs` — Add `EnableMfa()` method (sets MfaEnabled=true), `DisableMfa()` method (sets MfaEnabled=false)

**Note:** MFA tables have no `tenant_id` column — tenant-scoped transitively via `user_id`. Repos do NOT use `TenantContextHelper`.

---

### Step 2: MFA Proto, Service & Login Flow

**File to create:**
- `src/AuthService.Grpc/Protos/mfa.proto`

```protobuf
syntax = "proto3";
option csharp_namespace = "AuthService.Grpc.Protos";
package mfa;

service MfaService {
  rpc EnableMfa   (EnableMfaRequest)    returns (EnableMfaResponse);
  rpc VerifyMfa   (VerifyMfaRequest)    returns (VerifyMfaResponse);
  rpc DisableMfa  (DisableMfaRequest)   returns (DisableMfaResponse);
  rpc GenerateRecoveryCodes (GenerateRecoveryCodesRequest) returns (GenerateRecoveryCodesResponse);
}

message EnableMfaRequest {
  string user_id = 1;
}

message EnableMfaResponse {
  string secret      = 1;  // Base32 TOTP secret for QR code
  string qr_code_uri = 2;  // otpauth://totp/... URI
}

message VerifyMfaRequest {
  string user_id = 1;
  string code    = 2;  // 6-digit TOTP code or recovery code
}

message VerifyMfaResponse {
  bool   success       = 1;
  bool   is_confirmed  = 2;  // First successful verify confirms MFA
}

message DisableMfaRequest {
  string user_id = 1;
  string code    = 2;  // TOTP or recovery code to confirm disable
}

message DisableMfaResponse {
  bool success = 1;
}

message GenerateRecoveryCodesRequest {
  string user_id = 1;
}

message GenerateRecoveryCodesResponse {
  repeated string codes = 1;  // Plain-text codes (shown only once)
}
```

**Files to create:**
- `src/AuthService.Grpc/Services/MfaServiceImpl.cs` — follows existing pattern (primary constructor, sealed, GrpcTenantHelper for tenant ID). Logic:
  - `EnableMfa`: Generate TOTP secret (OtpNet), store encrypted in mfa_secrets (is_confirmed=false), return secret + QR URI. Do NOT set User.MfaEnabled yet.
  - `VerifyMfa`: Validate TOTP code against secret. If first verify and secret not confirmed → confirm it, set User.MfaEnabled=true, generate recovery codes, dispatch MfaEnabledEvent. Recovery codes also accepted.
  - `DisableMfa`: Verify code, then delete mfa_secret, set User.MfaEnabled=false.
  - `GenerateRecoveryCodes`: Invalidate old codes, generate new 8 codes (hashed for storage, plain returned once).
- `src/AuthService.Infrastructure/Persistence/Repositories/MfaRepository.cs` — raw SQL, follows existing pattern (no tenant context needed since mfa tables are scoped via user_id FK)
- `src/AuthService.Infrastructure/Persistence/Repositories/VerificationTokenRepository.cs` — raw SQL, no tenant context (scoped via user_id)
- `src/AuthService.Application/Features/Mfa/Dtos/EnableMfaDto.cs` — sealed record
- `src/AuthService.Application/Features/Mfa/Validators/VerifyMfaValidator.cs` — code not empty, 6-8 chars
- `src/AuthService.Infrastructure/Security/TotpService.cs` — implements `ITotpService`: GenerateSecret(), GenerateQrCodeUri(), VerifyCode(). Uses OtpNet library.

**New interface:**
- `src/AuthService.Application/Common/Interfaces/ITotpService.cs` — GenerateSecret(), GenerateQrCodeUri(issuer, email, secret), VerifyCode(secret, code)

**Full MFA Login Flow — modify AuthServiceImpl.Login:**

The current login returns `mfa_required = true` when `tenant.MfaRequired && !user.MfaEnabled`, but still issues tokens. The full MFA flow changes this behavior:

When MFA is required and the user has MFA enabled:
1. Login validates credentials successfully → does NOT issue tokens
2. Instead, returns `mfa_required = true` with a **pending MFA token** (short-lived, stored in Redis with key `mfa_pending:{user_id}:{tenant_id}`, TTL=5min)
3. The client calls `VerifyMfa` with the pending MFA token + TOTP code
4. `VerifyMfa` validates the code → if valid, issues the real access+refresh token pair

When MFA is required but the user hasn't set up MFA yet (`!user.MfaEnabled`):
- Login proceeds normally and returns `mfa_required = true` so the client knows to prompt MFA setup
- This is the current behavior — no change needed for this case

**Proto changes to `auth.proto`:**

```protobuf
// Add to LoginResponse:
string mfa_pending_token = 8;  // Short-lived token for MFA verification step
```

**Modify `AuthServiceImpl.Login`:**
- After successful password validation, check if tenant requires MFA AND user has MFA enabled
- If yes: generate a short-lived MFA pending token, store in Redis (`mfa_pending:{tenantId}:{userId}` → JSON with user ID, tenant ID, roles; TTL 5 min), return LoginResponse with `mfa_required=true` and `mfa_pending_token` set, **no access/refresh tokens**
- If MFA required but not enabled: current behavior (issue tokens + mfa_required=true flag)
- If MFA not required: current behavior (issue tokens + mfa_required=false)

**Add new RPC to auth.proto:**
```protobuf
rpc CompleteMfaLogin(CompleteMfaLoginRequest) returns (CompleteMfaLoginResponse);

message CompleteMfaLoginRequest {
  string mfa_pending_token = 1;
  string code               = 2;  // TOTP code
}

message CompleteMfaLoginResponse {
  string access_token            = 1;
  string refresh_token           = 2;
  int64  access_token_expires_at = 3;
  int64  refresh_token_expires_at = 4;
  string user_id                 = 5;
  string tenant_id               = 6;
}
```

**Modify `VerifyMfa` in MfaServiceImpl:**
- For the setup/confirmation flow: verify TOTP code against stored secret, confirm MFA, generate recovery codes
- This RPC is also used for MFA step during login if the client sends the pending token

**Add `CompleteMfaLogin` RPC to AuthServiceImpl:**
- Validate the pending token from Redis (`mfa_pending:{tenantId}:{userId}`)
- Verify TOTP code via IMfaRepository + ITotpService
- If valid: delete the pending token from Redis, issue real access+refresh tokens
- If invalid: return InvalidArgument

**Files to modify:**
- `src/AuthService.Grpc/Protos/auth.proto` — Add `mfa_pending_token` field to LoginResponse, add `CompleteMfaLogin` RPC
- `src/AuthService.Grpc/Services/AuthServiceImpl.cs` — Modify Login to handle MFA-required+enabled case, add CompleteMfaLogin RPC
- `src/AuthService.Grpc/AuthService.Grpc.csproj` — Add `<Protobuf Include="Protos\mfa.proto" GrpcServices="Server" />`; add NuGet `Otp.NET`
- `src/AuthService.Grpc/Program.cs` — Add `app.MapGrpcService<MfaServiceImpl>()`
- `src/AuthService.Infrastructure/AuthService.Infrastructure.csproj` — Add NuGet `Otp.NET`
- `src/AuthService.Infrastructure/InfrastructureServiceExtensions.cs` — Register `IMfaRepository`, `IVerificationTokenRepository`, `ITotpService`

---

### Step 3: Permission Cache & gRPC Permission Interceptor

**Files to create:**
- `src/AuthService.Infrastructure/Cache/PermissionCacheService.cs` — Implements `IPermissionCacheService`. Uses `ICacheService` (Redis). Key format: `permissions:{tenantId}:{userId}`. Methods: `GetPermissionsAsync(tenantId, userId)`, `SetPermissionsAsync(tenantId, userId, roles, permissions, expiry?)`, `InvalidatePermissionsAsync(tenantId, userId)`. Expiry = 15 min default.
- `src/AuthService.Application/Common/Interfaces/IPermissionCacheService.cs` — GetPermissions, SetPermissions, InvalidatePermissions
- `src/AuthService.Grpc/Interceptors/PermissionInterceptor.cs` — gRPC interceptor that runs after TenantResolutionInterceptor. Reads JWT claims for roles/permissions, or falls back to fetching from DB via RoleRepository + caching. Validates that the user has the required permission for the RPC method being called. Uses a static dictionary mapping gRPC method paths to required permissions (e.g., `/auth.AuthService/Register` → `user:write`). If no mapping exists, allow by default (whitelist approach for new RPCs). On `RoleAssigned`/`RoleUnassigned` events, invalidate the cache.

**Files to modify:**
- `src/AuthService.Infrastructure/InfrastructureServiceExtensions.cs` — Register `IPermissionCacheService` as Scoped
- `src/AuthService.Grpc/Program.cs` — Add `options.Interceptors.Add<PermissionInterceptor>()` after TenantResolutionInterceptor

**Cache invalidation strategy:** When `AssignRole` or `UnassignRole` is called in `RoleServiceImpl`, call `permissionCacheService.InvalidatePermissionsAsync(tenantId, userId)` to force a refresh on next request.

---

### Step 4: Verification Token Flow (Email Confirmation & Password Reset)

**Files to create:**
- `src/AuthService.Grpc/Protos/verification.proto`

```protobuf
syntax = "proto3";
option csharp_namespace = "AuthService.Grpc.Protos";
package verification;

service VerificationService {
  rpc VerifyEmail  (VerifyEmailRequest)  returns (VerifyEmailResponse);
  rpc RequestPasswordReset (RequestPasswordResetRequest) returns (RequestPasswordResetResponse);
  rpc ResetPassword (ResetPasswordRequest) returns (ResetPasswordResponse);
}

message VerifyEmailRequest {
  string token = 1;
}

message VerifyEmailResponse {
  bool success = 1;
}

message RequestPasswordResetRequest {
  string email = 1;
}

message RequestPasswordResetResponse {
  bool success = 1;  // Always true to prevent email enumeration
}

message ResetPasswordRequest {
  string token       = 1;
  string new_password = 2;
}

message ResetPasswordResponse {
  bool success = 1;
}
```

- `src/AuthService.Grpc/Services/VerificationServiceImpl.cs` — VerifyEmail (hash token, lookup, mark used, call user.ConfirmEmail()); RequestPasswordReset (find user, create verification token with purpose="password_reset", return success always); ResetPassword (validate token, hash new password, call user.SetPasswordHash())
- `src/AuthService.Application/Features/Verification/Dtos/` — DTOs for each operation
- `src/AuthService.Application/Features/Verification/Validators/` — Validators

**Files to modify:**
- `src/AuthService.Grpc/AuthService.Grpc.csproj` — Add proto reference
- `src/AuthService.Grpc/Program.cs` — Add `app.MapGrpcService<VerificationServiceImpl>()`
- `src/AuthService.Grpc/Interceptors/TenantResolutionInterceptor.cs` — Add tenant-free RPCs: `/verification.VerificationService/RequestPasswordReset` (uses email to resolve tenant), `/verification.VerificationService/VerifyEmail` (token is self-contained)
- `src/AuthService.Infrastructure/InfrastructureServiceExtensions.cs` — Register VerificationServiceImpl dependencies

**Note:** VerifyEmail and RequestPasswordReset need special handling — they can't rely on the standard tenant interceptor since the user may not be authenticated yet. These will be added to `TenantFreeRpcs` and resolve tenant context from the token's embedded data or by looking up the user's tenant.

---

### Step 5: Tenant Invitations

**Files to create:**
- `src/AuthService.Domain/Entities/TenantInvitation.cs` — sealed class extends Entity: TenantId, Email, TokenHash, RoleId?, InvitedBy, AcceptedAt, ExpiresAt, CreatedAt. Factory: `Create()`, `Accept()`, `Reconstitute()`. Computed: `IsExpired`, `IsAccepted`.
- `src/AuthService.Domain/Events/TenantInvitationAcceptedEvent.cs` — sealed record: `(Guid InvitationId, Guid TenantId, Guid UserId, string Email) : DomainEvent`
- `src/AuthService.Application/Common/Interfaces/ITenantInvitationRepository.cs` — GetByIdAsync, GetByTokenHashAsync, CreateAsync, UpdateAsync, ExistsAsync(tenantId, email)
- `src/AuthService.Infrastructure/Persistence/Repositories/TenantInvitationRepository.cs` — raw SQL, tenant-scoped with TenantContextHelper

**Proto additions to `tenant.proto`:**
```protobuf
// Add to TenantService:
rpc CreateInvitation (CreateInvitationRequest) returns (CreateInvitationResponse);
rpc AcceptInvitation (AcceptInvitationRequest) returns (AcceptInvitationResponse);

message CreateInvitationRequest {
  string email  = 1;
  string role_id = 2;  // optional — role to assign on accept
}

message CreateInvitationResponse {
  string invitation_id = 1;
  string token         = 2;  // Raw token (send in email, never stored plain)
  int64  expires_at    = 3;
}

message AcceptInvitationRequest {
  string token    = 1;
  string password = 2;  // User sets their password on accept
  string username = 3;  // User picks username on accept
}

message AcceptInvitationResponse {
  string user_id   = 1;
  string tenant_id = 2;
  string email     = 3;
}
```

**Files to create:**
- `src/AuthService.Grpc/Services/TenantServiceImpl.cs` (modify) — Add CreateInvitation and AcceptInvitation RPCs. CreateInvitation: generate token, hash it, store in tenant_invitations, return raw token. AcceptInvitation: hash token, find invitation, validate not expired/accepted, create user with password, assign pre-configured role, mark invitation accepted, dispatch event.
- `src/AuthService.Application/Features/Invitations/Dtos/CreateInvitationDto.cs`
- `src/AuthService.Application/Features/Invitations/Validators/CreateInvitationValidator.cs`
- `src/AuthService.Application/Features/Invitations/Validators/AcceptInvitationValidator.cs`

**Files to modify:**
- `src/AuthService.Grpc/Protos/tenant.proto` — Add invitation RPCs
- `src/AuthService.Grpc/Interceptors/TenantResolutionInterceptor.cs` — Add `/tenant.TenantService/AcceptInvitation` to TenantFreeRpcs (user isn't authenticated yet)
- `src/AuthService.Infrastructure/InfrastructureServiceExtensions.cs` — Register `ITenantInvitationRepository`

---

### Step 6: OAuth2/OIDC Provider (OpenIddict)

This is the largest step. OpenIddict runs as HTTP controllers alongside the gRPC server (OIDC is HTTP-based, not gRPC). The challenge: OpenIddict expects EF Core-style stores by default. We'll implement custom `IOpenIddictApplicationStore`, `IOpenIddictAuthorizationStore`, and `IOpenIddictScopeStore` backed by our raw SQL repositories.

**Approach: Custom OpenIddict stores with raw SQL (no EF Core)**

OpenIddict's core abstractions (`IOpenIddictApplicationStore`, `IOpenIddictAuthorizationStore`, `IOpenIddictTokenStore`) can be implemented against any data store. We'll implement them using our existing Npgsql + raw SQL pattern against the `oauth_clients`, `authorization_codes`, `user_consents`, and `signing_keys` tables.

**New NuGet packages:**
- `OpenIddict.AspNetCore` (in Grpc project — it's a web app already)
- `OpenIddict.EntityFrameworkCore` NOT used — we implement stores manually

**Files to create:**

- `src/AuthService.Application/Common/Interfaces/IOAuthClientRepository.cs` — GetByIdAsync, GetByClientIdAsync, CreateAsync, UpdateAsync, ListForTenantAsync, ValidateRedirectUriAsync
- `src/AuthService.Application/Common/Interfaces/IAuthorizationCodeRepository.cs` — GetByCodeHashAsync, CreateAsync, MarkRedeemedAsync
- `src/AuthService.Application/Common/Interfaces/IUserConsentRepository.cs` — GetAsync(tenantId, userId, clientId), CreateAsync, UpdateAsync
- `src/AuthService.Application/Common/Interfaces/ISigningKeyRepository.cs` — GetActiveAsync, CreateAsync, RotateAsync (deactivate old, activate new)
- `src/AuthService.Infrastructure/Persistence/Repositories/OAuthClientRepository.cs` — raw SQL, tenant-scoped with TenantContextHelper
- `src/AuthService.Infrastructure/Persistence/Repositories/AuthorizationCodeRepository.cs` — raw SQL, tenant-scoped
- `src/AuthService.Infrastructure/Persistence/Repositories/UserConsentRepository.cs` — raw SQL, tenant-scoped
- `src/AuthService.Infrastructure/Persistence/Repositories/SigningKeyRepository.cs` — raw SQL, NOT tenant-scoped (global)

- `src/AuthService.Infrastructure/OpenIddict/CustomOpenIddictApplicationStore.cs` — Implements `IOpenIddictApplicationStore`. Maps between OpenIddict's `OpenIddictApplicationModel` and our `oauth_clients` table via `IOAuthClientRepository`. Handles client_id, client_secret validation, redirect_uri validation, grant types, scopes, PKCE requirement.
- `src/AuthService.Infrastructure/OpenIddict/CustomOpenIddictAuthorizationStore.cs` — Implements `IOpenIddictAuthorizationStore`. Maps to `user_consents` table via `IUserConsentRepository`.
- `src/AuthService.Infrastructure/OpenIddict/CustomOpenIddictTokenStore.cs` — Implements `IOpenIddictTokenStore`. Maps to `authorization_codes` and `refresh_tokens` tables. Handles code redemption, token creation, revocation.
- `src/AuthService.Infrastructure/OpenIddict/CustomOpenIddictScopeStore.cs` — Implements `IOpenIddictScopeStore`. Simple in-memory scope store (openid, profile, email, offline_access) — no DB table needed for scopes.

- `src/AuthService.Grpc/Controllers/AuthorizationController.cs` — MVC controller with OpenIddict attributes:
  - `GET /authorize` — Shows consent/login UI (for API-only, redirect immediately with code). Validates client_id, redirect_uri, PKCE. Creates authorization_code. Resolves tenant from subdomain or client_id.
  - `POST /token` — Exchange authorization_code for tokens (with PKCE verification), or refresh_token grant. Issues ID token + access token.
  - `GET /userinfo` — Returns user claims from JWT. Requires Bearer token.
  - `GET /.well-known/openid-configuration` — Discovery document.
  - `GET /jwks` — JSON Web Key Set from `signing_keys` table.

- `src/AuthService.Grpc/Controllers/ConsentController.cs` — (Optional) Consent screen for user approval. Can be skipped for first-party clients or API-only flows.

- `src/AuthService.Infrastructure/Security/SigningKeyService.cs` — Manages `signing_keys` table. On startup: load active key or generate new RSA keypair, encrypt private key (AES-256 with config-provided key), store in DB. Provides public keys for JWKS endpoint. Replaces the ephemeral key fallback in JwtTokenService.

**Files to modify:**
- `src/AuthService.Grpc/AuthService.Grpc.csproj` — Add `OpenIddict.AspNetCore` NuGet
- `src/AuthService.Grpc/Program.cs` — Major changes:
  - Add MVC controllers: `builder.Services.AddControllers()` + `app.MapControllers()`
  - Add OpenIddict server: `builder.Services.AddOpenIddict().AddCore(...).AddServer(...).AddValidation(...)`
  - Register custom stores in OpenIddict core
  - Configure OpenIddict server: enable authorization_code flow, refresh_token flow, PKCE, disable implicit/hybrid
  - Replace ephemeral RSA key fallback in JwtTokenService with SigningKeyService
- `src/AuthService.Infrastructure/InfrastructureServiceExtensions.cs` — Register new repos, `SigningKeyService`
- `src/AuthService.Infrastructure/Security/JwtTokenService.cs` — Optionally refactor to load keys from `signing_keys` table via `SigningKeyService` instead of config
- `src/AuthService.Grpc/Interceptors/TenantResolutionInterceptor.cs` — Add OIDC endpoints to TenantFreeRpcs (tenant is resolved from client_id or subdomain in the controller, not from the interceptor)

**Tenant resolution for OIDC:** The `AuthorizationController` resolves the tenant independently:
1. Subdomain: `acme.auth.yourdomain.com` → resolve via `tenants.custom_domain` or subdomain extraction
2. `client_id` prefix: client IDs follow `{tenant_slug}_{client_name}` convention → extract slug → resolve tenant
3. The controller sets `SET LOCAL app.current_tenant_id` before any DB queries

**New domain event:**
- `src/AuthService.Domain/Events/AuthorizationCodeCreatedEvent.cs` — (optional, for audit)

---

### Step 7: Additional Domain Events

The build plan lists events that should be published but aren't yet.

**Files to create:**
- `src/AuthService.Domain/Events/UserLoggedInEvent.cs` — `(Guid UserId, Guid TenantId, string DeviceInfo) : DomainEvent`
- `src/AuthService.Domain/Events/PasswordChangedEvent.cs` — `(Guid UserId, Guid TenantId) : DomainEvent`
- `src/AuthService.Domain/Events/RoleAssignedEvent.cs` — `(Guid UserId, Guid TenantId, Guid RoleId, string RoleName) : DomainEvent`
- `src/AuthService.Domain/Events/AccountLockedEvent.cs` — `(Guid UserId, Guid TenantId, int FailedAttempts) : DomainEvent`

**Files to modify:**
- `src/AuthService.Grpc/Services/AuthServiceImpl.cs` — Dispatch `UserLoggedInEvent` after successful login, `AccountLockedEvent` when lockout triggered, `PasswordChangedEvent` if password change RPC is added
- `src/AuthService.Grpc/Services/RoleServiceImpl.cs` — Dispatch `RoleAssignedEvent` after AssignRole

---

### Step 8: Gateway & YARP Route Updates

**Files to modify:**
- `src/AuthService.Gateway/appsettings.json` — Add YARP routes for:
  - `roles-grpc-route`: `/roles.RoleService/{**catch-all}` → auth-grpc-cluster
  - `mfa-grpc-route`: `/mfa.MfaService/{**catch-all}` → auth-grpc-cluster
  - `verification-grpc-route`: `/verification.VerificationService/{**catch-all}` → auth-grpc-cluster
  - `oidc-authorize-route`: `GET /authorize` → auth-grpc-cluster (HTTP1 → gRPC-JSON transcoding)
  - `oidc-token-route`: `POST /token` → auth-grpc-cluster
  - `oidc-userinfo-route`: `GET /userinfo` → auth-grpc-cluster
  - `oidc-discovery-route`: `GET /.well-known/openid-configuration` → auth-grpc-cluster
  - `oidc-jwks-route`: `GET /jwks` → auth-grpc-cluster

- `src/AuthService.Gateway/Program.cs` — Add tenant resolution from subdomain for OIDC endpoints (extract subdomain from Host header, inject X-Tenant-ID)

---

## New NuGet Packages Summary

| Package | Project | Purpose |
|---------|---------|---------|
| `Otp.NET` | Infrastructure, Grpc | TOTP generation/verification |
| `OpenIddict.AspNetCore` | Grpc | OAuth2/OIDC server |

---

## Implementation Order (dependency chain)

```
Step 1 (MFA entities/repos) ──┐
                               ├──> Step 2 (MFA proto + service)
Step 3 (permission cache)     │
       │                      │
       ▼                      ▼
  (independent)           Step 4 (verification tokens) ──┐
                                                           ├──> Step 6 (OAuth2/OIDC)
Step 5 (tenant invitations) ──────────────────────────────┘
       │
       ▼
Step 7 (additional domain events) ──> Step 8 (gateway updates)
```

Steps 1, 3, and 5 can be done in parallel (no dependencies between them).
Step 2 depends on Step 1. Step 4 depends on Step 1. Step 6 depends on Steps 4 and 5.
Steps 7 and 8 are final polish.

---

## Verification

After each step:
1. `dotnet build src/AuthService.slnx` — ensure compilation
2. `docker compose up -d` — ensure infra is running
3. `dotnet run --project src/AuthService.Grpc` — verify startup (migrations run, no errors)

After all steps:
1. Use `grpcurl` to test new RPCs: `grpcurl -plaintext localhost:5100 list` should show all services
2. Test MFA flow: EnableMfa → VerifyMfa → GenerateRecoveryCodes → DisableMfa
3. Test verification: VerifyEmail, RequestPasswordReset, ResetPassword
4. Test invitations: CreateInvitation → AcceptInvitation
5. Test OIDC: `curl http://localhost:5101/.well-known/openid-configuration`
6. Test JWKS: `curl http://localhost:5101/jwks`
7. Verify permission cache: call GetPermissions twice, check Redis for cached key
8. Verify gateway routes: test through gateway port