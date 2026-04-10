using Grpc.Core;

namespace AuthService.Grpc.Helpers;

/// <summary>
/// Extracts the tenant ID that was resolved and stored by
/// <see cref="Interceptors.TenantResolutionInterceptor"/>.
/// </summary>
internal static class GrpcTenantHelper
{
    internal static Guid GetRequiredTenantId(ServerCallContext context)
    {
        if (context.UserState.TryGetValue("TenantId", out var value) && value is Guid tenantId)
            return tenantId;

        throw new RpcException(new Status(StatusCode.Internal,
            "Tenant ID was not set by the interceptor."));
    }
}
