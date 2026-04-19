namespace AuthService.Application.Features.Auth.Commands;

public sealed record RegisterUserCommand(
    Guid   TenantId,
    string Email,
    string Username,
    string Password,
    string? FirstName,
    string? LastName);

public sealed record RegisterUserResult(
    Guid   UserId,
    Guid   TenantId,
    string Email,
    string Username);
