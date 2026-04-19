namespace AuthService.Application.Features.Roles.Queries;

public sealed record ListRolesQuery(Guid TenantId);

public sealed record ListRolesResult(IReadOnlyList<RoleSummary> Roles);

public sealed record RoleSummary(Guid RoleId, string Name, string? Description, bool IsSystemRole);
