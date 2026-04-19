namespace AuthService.Application.Features.Auth.Commands;

public sealed record LogoutCommand(
    Guid    TenantId,
    string? AccessToken,
    string? RefreshToken);

public sealed record LogoutResult(bool Success);
