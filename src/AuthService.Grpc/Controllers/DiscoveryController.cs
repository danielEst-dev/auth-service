using AuthService.Application.Common.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Grpc.Controllers;

[ApiController]
public sealed class DiscoveryController(ISigningKeyService signingKeyService) : ControllerBase
{
    // ── GET /.well-known/openid-configuration ─────────────────────────────────

    [HttpGet("/.well-known/openid-configuration")]
    public IActionResult GetDiscoveryDocument()
    {
        var issuer = $"{Request.Scheme}://{Request.Host}";

        var doc = new
        {
            issuer,
            authorization_endpoint              = $"{issuer}/oauth/authorize",
            token_endpoint                      = $"{issuer}/oauth/token",
            userinfo_endpoint                   = $"{issuer}/oauth/userinfo",
            jwks_uri                            = $"{issuer}/oauth/jwks",
            response_types_supported            = new[] { "code" },
            grant_types_supported               = new[] { "authorization_code", "refresh_token" },
            subject_types_supported             = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" },
            code_challenge_methods_supported    = new[] { "S256" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "none" },
            scopes_supported                    = new[] { "openid", "profile", "email", "offline_access" },
            claims_supported                    = new[] { "sub", "iss", "aud", "exp", "iat", "jti",
                                                          "tenant_id", "email", "email_verified",
                                                          "given_name", "family_name", "preferred_username",
                                                          "auth_time", "nonce" }
        };

        return Ok(doc);
    }

    // ── GET /oauth/jwks ───────────────────────────────────────────────────────

    [HttpGet("/oauth/jwks")]
    public ContentResult GetJwks()
    {
        var json = signingKeyService.GetJwksJson();
        return Content(json, "application/json");
    }
}
