namespace AuthService.Application.Features.Auth.Dtos;

public sealed record RegisterUserDto(
    string Email,
    string Username,
    string Password,
    string? FirstName,
    string? LastName);
