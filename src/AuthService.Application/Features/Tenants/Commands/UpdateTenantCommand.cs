namespace AuthService.Application.Features.Tenants.Commands;

public sealed record UpdateTenantCommand(
    Guid    TenantId,
    string? Name,
    string? CustomDomain,
    bool    MfaRequired,
    int     SessionLifetimeMinutes);

public sealed record UpdateTenantResult(bool Success, DateTimeOffset UpdatedAt);
