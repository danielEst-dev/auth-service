using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.OAuth.Commands;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Grpc.Controllers;

/// <summary>
/// GET /oauth/authorize — Authorization Code + PKCE flow. The handler owns all policy;
/// this controller only maps the HTTP surface to the command and redirects on success.
/// Errors throw <see cref="Application.Common.Exceptions.OAuthException"/> which the
/// OAuth exception filter translates to redirect or JSON per RFC 6749 §4.1.2.1.
/// </summary>
[ApiController]
public sealed class AuthorizationController(
    ICommandHandler<AuthorizeCommand, AuthorizeResult> authorize) : ControllerBase
{
    [HttpGet("/oauth/authorize")]
    public async Task<IActionResult> Authorize(
        [FromQuery(Name = "client_id")]             string? clientId,
        [FromQuery(Name = "redirect_uri")]          string? redirectUri,
        [FromQuery(Name = "response_type")]         string? responseType,
        [FromQuery(Name = "scope")]                 string? scope,
        [FromQuery(Name = "state")]                 string? state,
        [FromQuery(Name = "code_challenge")]        string? codeChallenge,
        [FromQuery(Name = "code_challenge_method")] string? codeChallengeMethod,
        [FromQuery(Name = "nonce")]                 string? nonce,
        CancellationToken ct)
    {
        var result = await authorize.HandleAsync(
            new AuthorizeCommand(
                ClientId:            clientId,
                RedirectUri:         redirectUri,
                ResponseType:        responseType,
                Scope:               scope,
                State:               state,
                CodeChallenge:       codeChallenge,
                CodeChallengeMethod: codeChallengeMethod,
                Nonce:               nonce,
                CallerAccessToken:   ExtractBearerToken()),
            ct);

        return Redirect(result.CallbackUri);
    }

    private string? ExtractBearerToken()
    {
        var auth = Request.Headers.Authorization.FirstOrDefault();
        return auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? auth["Bearer ".Length..].Trim()
            : null;
    }
}
