using System.Security.Claims;
using AuthService.Application.Common.Interfaces;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Microsoft.AspNetCore.Http;

namespace AuthService.Grpc.Interceptors;

/// <summary>
/// Validates that the authenticated user has the required permission for the
/// gRPC method being invoked. Runs after <see cref="TenantResolutionInterceptor"/>.
///
/// Resolution strategy:
///   1. Read permissions from JWT claims (fastest — no DB hit).
///   2. Fall back to Redis cache → then DB (via IRoleRepository), then cache the result.
///   3. If no permission mapping exists for a method, allow by default.
///
/// Cache is invalidated when roles are assigned/unassigned (see RoleServiceImpl).
/// </summary>
public sealed class PermissionInterceptor(
    IPermissionCacheService permissionCacheService,
    IRoleRepository roleRepository,
    ILogger<PermissionInterceptor> logger) : Interceptor
{
    /// <summary>
    /// Maps gRPC method paths to the permission required to call them.
    /// Methods not listed here are allowed by default (open until explicitly locked down).
    /// </summary>
    private static readonly Dictionary<string, string> MethodPermissions = new(StringComparer.Ordinal)
    {
        // Auth
        ["/auth.AuthService/Register"]       = "user:create",
        // ValidateToken is public: it verifies signature + expiry + blacklist, leaking
        // nothing a valid token holder doesn't already have. Gating it on a caller
        // permission breaks service-to-service validation (the caller has no user JWT).
        // GetUserInfo self-check is handled inside AuthServiceImpl.GetUserInfo
        // so a user can always read their own profile without `user:read`.

        // Tenant management
        ["/tenant.TenantService/UpdateTenant"]    = "tenant:write",
        ["/tenant.TenantService/DeactivateTenant"] = "tenant:write",
        ["/tenant.TenantService/CreateInvitation"] = "invitation:create",

        // Roles
        ["/roles.RoleService/CreateRole"]   = "role:create",
        ["/roles.RoleService/AssignRole"]   = "role:assign",
        ["/roles.RoleService/UnassignRole"] = "role:assign",

        // MFA
        ["/mfa.MfaService/EnableMfa"]            = "mfa:write",
        ["/mfa.MfaService/DisableMfa"]           = "mfa:write",
        ["/mfa.MfaService/GenerateRecoveryCodes"] = "mfa:write",

        // Verification — tenant-free, no permission check needed
        // (VerifyEmail, RequestPasswordReset, ResetPassword are public)
    };

    /// <summary>
    /// Methods that are always allowed (login, public endpoints, MFA verify step).
    /// </summary>
    private static readonly HashSet<string> PublicMethods = new(StringComparer.Ordinal)
    {
        "/auth.AuthService/Login",
        "/auth.AuthService/CompleteMfaLogin",
        "/auth.AuthService/RefreshToken",
        "/auth.AuthService/ValidateToken",
        // Logout is public: the refresh token IS the credential being revoked,
        // and an expired access token must still be able to invalidate its refresh token.
        "/auth.AuthService/Logout",
        "/auth.AuthService/GetUserInfo", // self-check enforced in AuthServiceImpl.GetUserInfo
        "/tenant.TenantService/CreateTenant",
        "/tenant.TenantService/GetTenant",
        "/tenant.TenantService/AcceptInvitation",
        "/roles.RoleService/GetPermissions",
        "/roles.RoleService/ListRoles",
        "/mfa.MfaService/VerifyMfa",
        "/verification.VerificationService/VerifyEmail",
        "/verification.VerificationService/RequestPasswordReset",
        "/verification.VerificationService/ResetPassword",
    };

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        await CheckPermissionAsync(context);
        return await continuation(request, context);
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        await CheckPermissionAsync(context);
        await continuation(request, responseStream, context);
    }

    private async Task CheckPermissionAsync(ServerCallContext context)
    {
        var method = context.Method;

        // Public methods — no permission check
        if (PublicMethods.Contains(method))
            return;

        // No mapping — allow by default
        if (!MethodPermissions.TryGetValue(method, out var requiredPermission))
            return;

        var httpContext = context.GetHttpContext();
        if (httpContext.User.Identity?.IsAuthenticated != true)
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Authentication required."));

        // Try JWT claims first (no DB/cache hit)
        var jwtPermissions = httpContext.User.FindAll("permission").Select(c => c.Value).ToList();
        if (jwtPermissions.Count > 0)
        {
            if (jwtPermissions.Contains(requiredPermission))
                return;

            throw new RpcException(new Status(StatusCode.PermissionDenied,
                $"Permission '{requiredPermission}' is required."));
        }

        // Fall back to cache → DB
        if (!context.UserState.TryGetValue("TenantId", out var tenantObj) || tenantObj is not Guid tenantId)
            return; // No tenant context — can't check, allow (tenant interceptor handles this)

        var userIdClaim = httpContext.User.FindFirst("sub")?.Value;
        if (userIdClaim is null || !Guid.TryParse(userIdClaim, out var userId))
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Invalid user identity."));

        var cached = await permissionCacheService.GetPermissionsAsync(tenantId, userId, context.CancellationToken);
        if (cached is null)
        {
            var roles       = await roleRepository.GetRoleNamesForUserAsync(tenantId, userId, context.CancellationToken);
            var permissions = await roleRepository.GetPermissionNamesForUserAsync(tenantId, userId, context.CancellationToken);
            cached = new CachedPermissions(roles, permissions);
            await permissionCacheService.SetPermissionsAsync(tenantId, userId, cached, context.CancellationToken);
        }

        if (!cached.Permissions.Contains(requiredPermission))
        {
            logger.LogWarning(
                "Permission denied: user {UserId} lacks '{Permission}' for {Method} in tenant {TenantId}",
                userId, requiredPermission, method, tenantId);

            throw new RpcException(new Status(StatusCode.PermissionDenied,
                $"Permission '{requiredPermission}' is required."));
        }
    }
}