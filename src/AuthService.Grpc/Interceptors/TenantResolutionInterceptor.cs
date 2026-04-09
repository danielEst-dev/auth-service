using System.Diagnostics;
using AuthService.Application.Common.Interfaces;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Serilog.Context;

namespace AuthService.Grpc.Interceptors;

/// <summary>
/// Resolves the current tenant from gRPC metadata and stores it in
/// <c>context.UserState["TenantId"]</c> for downstream handlers.
/// Each repository then sets <c>SET LOCAL app.current_tenant_id</c>
/// within its own transaction so RLS policies apply correctly.
///
/// Resolution order:
///   1. x-tenant-id header (explicit — for M2M / API clients)
///   2. tenant_id claim in the Bearer JWT (for authenticated user calls)
///
/// RPCs listed in <see cref="TenantFreeRpcs"/> are exempt from resolution
/// (e.g. CreateTenant, which bootstraps a new tenant and has no tenant context yet).
/// </summary>
public sealed class TenantResolutionInterceptor(ITenantRepository tenantRepository) : Interceptor
{
    // RPCs that may be called without an existing tenant context.
    private static readonly HashSet<string> TenantFreeRpcs = new(StringComparer.Ordinal)
    {
        "/tenant.TenantService/CreateTenant",
    };

    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        if (!TenantFreeRpcs.Contains(context.Method))
        {
            var tenantId = await ResolveTenant(context);
            using var _ = LogContext.PushProperty("TenantId", tenantId);
            Activity.Current?.SetTag("tenant.id", tenantId.ToString());
            return await continuation(request, context);
        }

        return await continuation(request, context);
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        if (!TenantFreeRpcs.Contains(context.Method))
        {
            var tenantId = await ResolveTenant(context);
            using var _ = LogContext.PushProperty("TenantId", tenantId);
            Activity.Current?.SetTag("tenant.id", tenantId.ToString());
            await continuation(request, responseStream, context);
            return;
        }

        await continuation(request, responseStream, context);
    }

    private async Task<Guid> ResolveTenant(ServerCallContext context)
    {
        var tenantIdStr = ResolveRawTenantId(context);

        if (string.IsNullOrWhiteSpace(tenantIdStr))
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Tenant could not be resolved. Provide x-tenant-id header or a valid JWT."));

        if (!Guid.TryParse(tenantIdStr, out var tenantId))
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "Invalid tenant ID format — must be a valid UUID."));

        var exists = await tenantRepository.ExistsAsync(tenantId, context.CancellationToken);
        if (!exists)
            throw new RpcException(new Status(StatusCode.NotFound,
                $"Tenant '{tenantId}' not found or is inactive."));

        // Store for downstream handlers to consume without re-parsing
        context.UserState["TenantId"] = tenantId;
        return tenantId;
    }

    private static string? ResolveRawTenantId(ServerCallContext context)
    {
        // 1. Explicit header — highest priority (M2M, tests, internal services)
        var headerValue = context.RequestHeaders.GetValue("x-tenant-id");
        if (!string.IsNullOrWhiteSpace(headerValue))
            return headerValue;

        // 2. JWT tenant_id claim — for browser/mobile clients
        var httpContext = context.GetHttpContext();
        var claim = httpContext.User.FindFirst("tenant_id");
        return claim?.Value;
    }
}
