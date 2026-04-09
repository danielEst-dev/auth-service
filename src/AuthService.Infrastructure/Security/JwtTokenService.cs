using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Infrastructure.Security;

public sealed class JwtTokenService : ITokenService
{
    private readonly RsaSecurityKey _signingKey;
    private readonly RsaSecurityKey _validationKey;
    private readonly string _issuer;
    private readonly TimeSpan _accessTokenLifetime;
    private readonly TimeSpan _refreshTokenLifetime;

    public JwtTokenService(IConfiguration configuration)
    {
        var jwtSection = configuration.GetSection("Jwt");
        _issuer = jwtSection["Issuer"] ?? "auth-service";
        _accessTokenLifetime = TimeSpan.FromMinutes(
            jwtSection.GetValue<int>("AccessTokenLifetimeMinutes", 15));
        _refreshTokenLifetime = TimeSpan.FromDays(
            jwtSection.GetValue<int>("RefreshTokenLifetimeDays", 7));

        var privateKeyPem = jwtSection["PrivateKeyPem"];
        var publicKeyPem  = jwtSection["PublicKeyPem"];

        if (!string.IsNullOrWhiteSpace(privateKeyPem) && !string.IsNullOrWhiteSpace(publicKeyPem))
        {
            // Load from config (appsettings.Local.json / env var / secret)
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);
            _signingKey = new RsaSecurityKey(rsa);

            var rsaPublic = RSA.Create();
            rsaPublic.ImportFromPem(publicKeyPem);
            _validationKey = new RsaSecurityKey(rsaPublic);
        }
        else
        {
            // Dev fallback: generate an ephemeral key pair on startup
            // Tokens will be invalidated on restart — acceptable for development only
            var rsa = RSA.Create(2048);
            _signingKey   = new RsaSecurityKey(rsa);
            _validationKey = new RsaSecurityKey(rsa);
        }
    }

    public TokenPair GenerateTokenPair(
        User user,
        Tenant tenant,
        IEnumerable<string> roles,
        IEnumerable<string> permissions)
    {
        var now = DateTimeOffset.UtcNow;

        // Access token lifetime: tenant override → global default
        var accessLifetime = tenant.AccessTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.AccessTokenLifetimeSeconds.Value)
            : _accessTokenLifetime;

        var refreshLifetime = tenant.RefreshTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value)
            : _refreshTokenLifetime;

        var accessExpiry  = now.Add(accessLifetime);
        var refreshExpiry = now.Add(refreshLifetime);

        var roleList       = roles.ToList();
        var permissionList = permissions.ToList();

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub,  user.Id.ToString()),
            new(JwtRegisteredClaimNames.Jti,  Guid.CreateVersion7().ToString()),
            new(JwtRegisteredClaimNames.Iat,  now.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("tenant_id", tenant.Id.ToString()),
            new("email",     user.Email),
            new("username",  user.Username),
        };

        claims.AddRange(roleList.Select(r => new Claim("role", r)));
        claims.AddRange(permissionList.Select(p => new Claim("permission", p)));

        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject            = new ClaimsIdentity(claims),
            Issuer             = _issuer,
            Expires            = accessExpiry.UtcDateTime,
            SigningCredentials = credentials
        };

        var handler     = new JwtSecurityTokenHandler();
        var accessToken = handler.CreateEncodedJwt(tokenDescriptor);

        var rawRefresh = GenerateRawRefreshToken();

        return new TokenPair(
            AccessToken:           accessToken,
            RefreshToken:          rawRefresh,
            AccessTokenExpiry:     accessExpiry,
            RefreshTokenExpiry:    refreshExpiry);
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
            IssuerSigningKey         = _validationKey,
            ClockSkew                = TimeSpan.FromSeconds(30)
        };

        try
        {
            return handler.ValidateToken(token, parameters, out _);
        }
        catch
        {
            return null;
        }
    }

    public string GenerateRawRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes);
    }

    public string HashRefreshToken(string rawToken)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(rawToken);
        var hash  = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
