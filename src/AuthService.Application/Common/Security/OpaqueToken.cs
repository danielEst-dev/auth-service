using System.Security.Cryptography;
using System.Text;

namespace AuthService.Application.Common.Security;

/// <summary>
/// URL-safe random-token utilities. Used for invitations, email verification, and password
/// reset — anything where we issue a one-time bearer string and store only its hash.
/// Centralized here so the generation and hashing stay in lockstep across callers.
/// </summary>
public static class OpaqueToken
{
    /// <summary>32 random bytes, base64url-encoded (~43 chars). Sufficient entropy for links.</summary>
    public static string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    /// <summary>Lowercase hex SHA-256 of the raw token — what we persist. Collision-free in practice.</summary>
    public static string Hash(string rawToken) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken))).ToLowerInvariant();
}
