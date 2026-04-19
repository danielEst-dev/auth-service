namespace AuthService.Application.Features.Roles.Queries;

public sealed record GetPermissionsQuery(Guid TenantId, Guid UserId);

public sealed record GetPermissionsResult(IReadOnlyList<string> Roles, IReadOnlyList<string> Permissions);
