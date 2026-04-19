namespace AuthService.Application.Features.Roles.Commands;

public sealed record AssignRoleCommand(Guid TenantId, Guid UserId, Guid RoleId, Guid? AssignedBy);

public sealed record AssignRoleResult(bool Success);
