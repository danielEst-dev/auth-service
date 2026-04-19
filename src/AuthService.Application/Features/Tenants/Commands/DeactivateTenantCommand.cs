namespace AuthService.Application.Features.Tenants.Commands;

public sealed record DeactivateTenantCommand(Guid TenantId);

public sealed record DeactivateTenantResult(bool Success);
