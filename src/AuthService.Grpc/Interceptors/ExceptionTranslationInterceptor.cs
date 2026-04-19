using AuthService.Application.Common.Exceptions;
using FluentValidation;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace AuthService.Grpc.Interceptors;

/// <summary>
/// Translates Application-layer exceptions into gRPC statuses in one place. Without this
/// every handler-backed RPC would need its own try/catch ladder — the same mapping
/// repeated per adapter, and every new exception type requiring every adapter to be
/// updated.
///
/// Runs OUTSIDE the <see cref="UnitOfWorkInterceptor"/> so the UoW rollback happens
/// first; by the time we catch here the transaction is already rolled back, we're just
/// translating the error for the wire.
///
/// RpcExceptions thrown directly (e.g. by Tenant/Permission interceptors) pass through
/// unchanged — gRPC plumbing handles them as-is.
/// </summary>
public sealed class ExceptionTranslationInterceptor : Interceptor
{
    public override async Task<TResponse> UnaryServerHandler<TRequest, TResponse>(
        TRequest request,
        ServerCallContext context,
        UnaryServerMethod<TRequest, TResponse> continuation)
    {
        try { return await continuation(request, context); }
        catch (RpcException) { throw; }
        catch (Exception ex) { throw Translate(ex); }
    }

    public override async Task ServerStreamingServerHandler<TRequest, TResponse>(
        TRequest request,
        IServerStreamWriter<TResponse> responseStream,
        ServerCallContext context,
        ServerStreamingServerMethod<TRequest, TResponse> continuation)
    {
        try { await continuation(request, responseStream, context); }
        catch (RpcException) { throw; }
        catch (Exception ex) { throw Translate(ex); }
    }

    private static RpcException Translate(Exception ex) => ex switch
    {
        ValidationException v        => new RpcException(new Status(StatusCode.InvalidArgument,
                                            string.Join("; ", v.Errors.Select(e => e.ErrorMessage)))),
        ConflictException c          => new RpcException(new Status(StatusCode.AlreadyExists,     c.Message)),
        AuthenticationException a    => new RpcException(new Status(StatusCode.Unauthenticated,   a.Message)),
        AuthorizationException a     => new RpcException(new Status(StatusCode.PermissionDenied,  a.Message)),
        NotFoundException n          => new RpcException(new Status(StatusCode.NotFound,          n.Message)),
        RateLimitedException r       => new RpcException(new Status(StatusCode.ResourceExhausted, r.Message)),
        _                            => new RpcException(new Status(StatusCode.Internal,          "Internal server error.")),
    };
}
