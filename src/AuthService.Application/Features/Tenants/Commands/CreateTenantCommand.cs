namespace AuthService.Application.Features.Tenants.Commands;

public sealed record CreateTenantCommand(string Slug, string Name, string? Plan);

public sealed record CreateTenantResult(
    Guid   TenantId,
    string Slug,
    string Name,
    string Plan,
    DateTimeOffset CreatedAt);
