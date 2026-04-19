namespace AuthService.Application.Features.Auth.Commands;

public sealed record CompleteMfaLoginCommand(
    Guid   TenantId,
    string MfaPendingToken,
    string Code);

public sealed record CompleteMfaLoginResult(
    string         AccessToken,
    string         RefreshToken,
    DateTimeOffset AccessTokenExpiry,
    DateTimeOffset RefreshTokenExpiry,
    Guid           UserId,
    Guid           TenantId);
