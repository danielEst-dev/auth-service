using AuthService.Application.Common.Interfaces;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace AuthService.Grpc.Interceptors;

/// <summary>
/// Wraps every gRPC call in a single unit-of-work transaction. Begins on request arrival
/// (after tenant resolution), commits on normal return, rolls back on any exception
/// (including <see cref="RpcException"/> thrown from validation/auth guards).
///
/// This is what turns the outbox from "near-atomic" into fully transactional: the business
/// writes AND the outbox insert share one transaction, so either both land or neither does.
/// </summary>
public sealed class UnitOfWorkInterceptor(IDbContext dbContext) : Interceptor
{
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        var tenantId = ExtractTenantId(context);
        await dbContext.BeginAsync(tenantId, context.CancellationToken);
        try
        {
            var response = await continuation(request, context);
            await dbContext.CommitAsync(context.CancellationToken);
            return response;
        }
        catch
        {
            await dbContext.RollbackAsync(context.CancellationToken);
            throw;
        }
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        var tenantId = ExtractTenantId(context);
        await dbContext.BeginAsync(tenantId, context.CancellationToken);
        try
        {
            await continuation(request, responseStream, context);
            await dbContext.CommitAsync(context.CancellationToken);
        }
        catch
        {
            await dbContext.RollbackAsync(context.CancellationToken);
            throw;
        }
    }

    private static Guid? ExtractTenantId(ServerCallContext context) =>
        context.UserState.TryGetValue("TenantId", out var v) && v is Guid g ? g : null;
}
