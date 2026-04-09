namespace AuthService.Application.Features.Tenants.Dtos;

public sealed record CreateTenantDto(
    string Slug,
    string Name,
    string Plan = "free");
