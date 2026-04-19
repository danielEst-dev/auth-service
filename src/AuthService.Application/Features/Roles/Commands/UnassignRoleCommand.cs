namespace AuthService.Application.Features.Roles.Commands;

public sealed record UnassignRoleCommand(Guid TenantId, Guid UserId, Guid RoleId);

public sealed record UnassignRoleResult(bool Success);
