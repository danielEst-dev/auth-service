using System.Security.Cryptography;
using System.Text.Json;
using AuthService.Domain.Entities;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Infrastructure.Security;

/// <summary>
/// Serializes a list of <see cref="SigningKey"/> entities into the JWKS
/// <c>{ "keys": [...] }</c> envelope required by the <c>/jwks</c> endpoint.
/// </summary>
public interface IJwksBuilder
{
    string Build(IEnumerable<SigningKey> keys);
}

public sealed class JwksBuilder : IJwksBuilder
{
    public string Build(IEnumerable<SigningKey> keys) =>
        JsonSerializer.Serialize(new { keys = keys.Select(BuildJwk).ToList() });

    private static object BuildJwk(SigningKey key)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(key.PublicKeyPem);
        var p = rsa.ExportParameters(includePrivateParameters: false);

        return new
        {
            kty = "RSA",
            kid = key.Kid,
            use = "sig",
            alg = "RS256",
            n   = Base64UrlEncoder.Encode(p.Modulus!),
            e   = Base64UrlEncoder.Encode(p.Exponent!),
        };
    }
}
