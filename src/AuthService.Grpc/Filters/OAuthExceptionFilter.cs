using AuthService.Application.Common.Exceptions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AuthService.Grpc.Filters;

/// <summary>
/// Translates <see cref="OAuthException"/> thrown by OIDC handlers into the two response
/// shapes the spec allows: a 302 to <c>redirect_uri</c> with <c>error</c>/<c>state</c>
/// query params, or a JSON body with HTTP status. Runs before <see cref="UnitOfWorkActionFilter"/>
/// would rollback — the filter order doesn't matter because both handle the exception idempotently.
/// </summary>
public sealed class OAuthExceptionFilter : IAsyncExceptionFilter
{
    public Task OnExceptionAsync(ExceptionContext context)
    {
        if (context.Exception is not OAuthException ex) return Task.CompletedTask;

        context.ExceptionHandled = true;

        if (!string.IsNullOrWhiteSpace(ex.RedirectUri))
        {
            var uri = $"{ex.RedirectUri}?error={Uri.EscapeDataString(ex.Error)}"
                    + $"&error_description={Uri.EscapeDataString(ex.ErrorDescription)}";
            if (!string.IsNullOrWhiteSpace(ex.State))
                uri += $"&state={Uri.EscapeDataString(ex.State)}";

            context.Result = new RedirectResult(uri);
            return Task.CompletedTask;
        }

        context.Result = new JsonResult(new { error = ex.Error, error_description = ex.ErrorDescription })
        {
            StatusCode = ex.StatusCode,
        };
        return Task.CompletedTask;
    }
}
