using AuthService.Application.Common.Interfaces;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AuthService.Grpc.Filters;

/// <summary>
/// MVC equivalent of <see cref="Interceptors.UnitOfWorkInterceptor"/> — wraps OIDC
/// controller actions in a per-request UoW transaction.
///
/// OIDC endpoints resolve the tenant inside the action (from the OAuth client row), so
/// the filter can't pre-set tenant context. It begins with no tenant; actions that issue
/// tenant-scoped writes can call <c>IDbContext.BeginAsync(tenantId)</c> themselves if
/// they need RLS. For the current <c>/oauth/authorize</c> and <c>/oauth/token</c> flows,
/// RLS is enforced via explicit <c>tenant_id</c> filters in the SQL.
/// </summary>
public sealed class UnitOfWorkActionFilter(IDbContext dbContext) : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var ct = context.HttpContext.RequestAborted;
        await dbContext.BeginAsync(null, ct);
        try
        {
            var executed = await next();
            if (executed.Exception is not null)
            {
                await dbContext.RollbackAsync(ct);
                return;
            }
            await dbContext.CommitAsync(ct);
        }
        catch
        {
            await dbContext.RollbackAsync(ct);
            throw;
        }
    }
}
