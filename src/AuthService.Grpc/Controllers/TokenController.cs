using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.OAuth.Commands;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Grpc.Controllers;

/// <summary>
/// POST /oauth/token — dispatches on <c>grant_type</c> to the matching handler. New grants
/// (client_credentials, device_code) plug in as additional cases here without touching the
/// existing handlers.
/// </summary>
[ApiController]
public sealed class TokenController(
    ICommandHandler<ExchangeAuthorizationCodeCommand, TokenExchangeResult> exchangeAuthorizationCode,
    ICommandHandler<RefreshOAuthTokenCommand,         TokenExchangeResult> refreshOAuthToken) : ControllerBase
{
    [HttpPost("/oauth/token")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Token([FromForm] IFormCollection form, CancellationToken ct)
    {
        var grantType = form["grant_type"].FirstOrDefault();

        var result = grantType switch
        {
            "authorization_code" => await exchangeAuthorizationCode.HandleAsync(
                new ExchangeAuthorizationCodeCommand(
                    ClientId:     form["client_id"].FirstOrDefault(),
                    ClientSecret: form["client_secret"].FirstOrDefault(),
                    Code:         form["code"].FirstOrDefault(),
                    RedirectUri:  form["redirect_uri"].FirstOrDefault(),
                    CodeVerifier: form["code_verifier"].FirstOrDefault()),
                ct),

            "refresh_token" => await refreshOAuthToken.HandleAsync(
                new RefreshOAuthTokenCommand(
                    ClientId:     form["client_id"].FirstOrDefault(),
                    ClientSecret: form["client_secret"].FirstOrDefault(),
                    RefreshToken: form["refresh_token"].FirstOrDefault()),
                ct),

            _ => throw new OAuthException("unsupported_grant_type", $"Grant type '{grantType}' is not supported."),
        };

        var response = new Dictionary<string, object?>
        {
            ["access_token"] = result.AccessToken,
            ["token_type"]   = result.TokenType,
            ["expires_in"]   = result.ExpiresIn,
            ["scope"]        = result.Scope,
        };
        if (result.IdToken      is not null) response["id_token"]      = result.IdToken;
        if (result.RefreshToken is not null) response["refresh_token"] = result.RefreshToken;

        return Ok(response);
    }
}
