namespace AuthService.Application.Features.Auth.Commands;

public sealed record RefreshTokenCommand(
    Guid    TenantId,
    string  RefreshToken,
    string  PeerIp);

public sealed record RefreshTokenResult(
    string         AccessToken,
    string         RefreshToken,
    DateTimeOffset AccessTokenExpiry,
    DateTimeOffset RefreshTokenExpiry);
