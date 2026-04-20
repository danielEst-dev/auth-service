using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.OAuth.Queries;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Grpc.Controllers;

/// <summary>GET /oauth/userinfo — returns claims for the user identified by the Bearer token.</summary>
[ApiController]
public sealed class UserInfoController(
    IQueryHandler<GetOidcUserInfoQuery, GetOidcUserInfoResult> getUserInfo) : ControllerBase
{
    [HttpGet("/oauth/userinfo")]
    public async Task<IActionResult> GetUserInfo(CancellationToken ct)
    {
        var result = await getUserInfo.HandleAsync(new GetOidcUserInfoQuery(ExtractBearerToken()), ct);
        return Ok(result.Claims);
    }

    private string? ExtractBearerToken()
    {
        var auth = Request.Headers.Authorization.FirstOrDefault();
        return auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? auth["Bearer ".Length..].Trim()
            : null;
    }
}
