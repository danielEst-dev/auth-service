namespace AuthService.Application.Features.Roles.Commands;

public sealed record CreateRoleCommand(Guid TenantId, string Name, string? Description);

public sealed record CreateRoleResult(Guid RoleId, Guid TenantId, string Name, DateTimeOffset CreatedAt);
