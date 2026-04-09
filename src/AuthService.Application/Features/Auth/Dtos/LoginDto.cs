namespace AuthService.Application.Features.Auth.Dtos;

public sealed record LoginDto(
    string Email,
    string Password,
    string? DeviceInfo,
    string? IpAddress);
