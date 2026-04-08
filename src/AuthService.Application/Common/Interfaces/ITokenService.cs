using System.Security.Claims;
using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public sealed record TokenPair(
    string AccessToken,
    string RefreshToken,
    DateTimeOffset AccessTokenExpiry,
    DateTimeOffset RefreshTokenExpiry);

public interface ITokenService
{
    TokenPair GenerateTokenPair(
        User user,
        Tenant tenant,
        IEnumerable<string> roles,
        IEnumerable<string> permissions);

    ClaimsPrincipal? ValidateAccessToken(string token);

    string HashRefreshToken(string rawToken);

    string GenerateRawRefreshToken();
}