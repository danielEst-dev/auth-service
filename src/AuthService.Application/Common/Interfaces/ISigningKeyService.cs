namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Provides RSA signing key material for JWT token issuance and the JWKS endpoint.
/// Loaded once on startup from the signing_keys table (or generated if none exists).
/// Consumers in Infrastructure/Grpc cast to the concrete type or inject the concrete service directly.
/// </summary>
public interface ISigningKeyService
{
    /// <summary>The key ID (kid) header value for the active key.</summary>
    string GetKeyId();

    /// <summary>All public keys serialized as a JWKS JSON object (the { keys: [...] } envelope).</summary>
    string GetJwksJson();
}
