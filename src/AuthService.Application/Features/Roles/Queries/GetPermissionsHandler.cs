using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;

namespace AuthService.Application.Features.Roles.Queries;

public sealed class GetPermissionsHandler(IRoleRepository roleRepository)
    : IQueryHandler<GetPermissionsQuery, GetPermissionsResult>
{
    public async Task<GetPermissionsResult> HandleAsync(GetPermissionsQuery query, CancellationToken ct = default)
    {
        var roles       = await roleRepository.GetRoleNamesForUserAsync(query.TenantId, query.UserId, ct);
        var permissions = await roleRepository.GetPermissionNamesForUserAsync(query.TenantId, query.UserId, ct);
        return new GetPermissionsResult(roles, permissions);
    }
}
