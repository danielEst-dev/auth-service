using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Infrastructure.Security;

/// <summary>
/// Issues and validates all JWTs in the system — gRPC access tokens, OIDC access tokens,
/// and OIDC ID tokens. All tokens are signed with the single RSA keypair managed by
/// <see cref="SigningKeyService"/>, so JWKS publishes the public half for every token type.
/// </summary>
public sealed class JwtTokenService(
    SigningKeyService signingKeyService,
    IConfiguration configuration) : ITokenService
{
    private readonly string _issuer = configuration["Jwt:Issuer"] ?? "auth-service";
    private readonly TimeSpan _accessTokenLifetime = TimeSpan.FromMinutes(
        configuration.GetValue<int>("Jwt:AccessTokenLifetimeMinutes", 15));
    private readonly TimeSpan _refreshTokenLifetime = TimeSpan.FromDays(
        configuration.GetValue<int>("Jwt:RefreshTokenLifetimeDays", 7));

    // ── gRPC / internal access tokens ─────────────────────────────────────────

    public TokenPair GenerateTokenPair(
        User user, Tenant tenant,
        IEnumerable<string> roles, IEnumerable<string> permissions)
    {
        var now = DateTimeOffset.UtcNow;
        var accessLifetime = tenant.AccessTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.AccessTokenLifetimeSeconds.Value)
            : _accessTokenLifetime;
        var refreshLifetime = tenant.RefreshTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value)
            : _refreshTokenLifetime;

        var accessExpiry  = now.Add(accessLifetime);
        var refreshExpiry = now.Add(refreshLifetime);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString()),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("tenant_id", tenant.Id.ToString()),
            new("email",     user.Email),
            new("username",  user.Username),
        };
        claims.AddRange(roles.Select(r => new Claim("role", r)));
        claims.AddRange(permissions.Select(p => new Claim("permission", p)));

        var accessToken = Sign(claims, accessExpiry, audience: null);
        var rawRefresh  = GenerateRawRefreshToken();

        return new TokenPair(accessToken, rawRefresh, accessExpiry, refreshExpiry);
    }

    public ClaimsPrincipal? ValidateAccessToken(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var parameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = _issuer,
            ValidateAudience         = false,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = signingKeyService.GetSigningKey(),
            ClockSkew                = TimeSpan.FromSeconds(30)
        };

        try { return handler.ValidateToken(token, parameters, out _); }
        catch { return null; }
    }

    // ── OIDC tokens ───────────────────────────────────────────────────────────

    public (string Token, int ExpiresInSeconds) IssueOidcAccessToken(
        User user, Tenant tenant, OAuthClient client, IEnumerable<string> scopes)
    {
        var now = DateTimeOffset.UtcNow;
        var lifetimeSeconds = client.AccessTokenLifetime
            ?? tenant.AccessTokenLifetimeSeconds
            ?? (int)_accessTokenLifetime.TotalSeconds;
        var expiry = now.AddSeconds(lifetimeSeconds);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString()),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("tenant_id", tenant.Id.ToString()),
            new("scope",     string.Join(' ', scopes)),
        };

        return (Sign(claims, expiry, audience: client.ClientId), lifetimeSeconds);
    }

    public string IssueIdToken(
        User user, Tenant tenant, OAuthClient client,
        IEnumerable<string> scopes, string? nonce)
    {
        var now = DateTimeOffset.UtcNow;
        var expiry = now.AddMinutes(60); // ID tokens are short-lived per OIDC convention
        var scopeList = scopes.ToList();

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.CreateVersion7().ToString()),
            new(JwtRegisteredClaimNames.Iat, now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("tenant_id", tenant.Id.ToString()),
            new("auth_time", (user.LastLoginAt ?? now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        if (!string.IsNullOrWhiteSpace(nonce))
            claims.Add(new Claim("nonce", nonce));

        if (scopeList.Contains("email", StringComparer.OrdinalIgnoreCase))
        {
            claims.Add(new Claim("email", user.Email));
            claims.Add(new Claim("email_verified", user.IsEmailConfirmed.ToString().ToLowerInvariant(), ClaimValueTypes.Boolean));
        }

        if (scopeList.Contains("profile", StringComparer.OrdinalIgnoreCase))
        {
            if (user.FirstName is not null) claims.Add(new Claim("given_name", user.FirstName));
            if (user.LastName is not null)  claims.Add(new Claim("family_name", user.LastName));
            claims.Add(new Claim("preferred_username", user.Username));
        }

        return Sign(claims, expiry, audience: client.ClientId);
    }

    // ── Refresh tokens ────────────────────────────────────────────────────────

    public string GenerateRawRefreshToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    public string HashRefreshToken(string rawToken)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(rawToken);
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }

    // ── Signing primitive ─────────────────────────────────────────────────────

    private string Sign(IEnumerable<Claim> claims, DateTimeOffset expiry, string? audience)
    {
        var signingKey = signingKeyService.GetSigningKey();
        signingKey.KeyId = signingKeyService.GetKeyId();

        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);
        var descriptor = new SecurityTokenDescriptor
        {
            Subject            = new ClaimsIdentity(claims),
            Issuer             = _issuer,
            Audience           = audience,
            Expires            = expiry.UtcDateTime,
            SigningCredentials = credentials,
        };

        return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
    }
}
