namespace AuthService.Application.Features.OAuth.Commands;

public sealed record RefreshOAuthTokenCommand(
    string? ClientId,
    string? ClientSecret,
    string? RefreshToken);
