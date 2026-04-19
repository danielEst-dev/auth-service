using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;

namespace AuthService.Application.Features.Roles.Queries;

public sealed class ListRolesHandler(IRoleRepository roleRepository)
    : IQueryHandler<ListRolesQuery, ListRolesResult>
{
    public async Task<ListRolesResult> HandleAsync(ListRolesQuery query, CancellationToken ct = default)
    {
        var roles = await roleRepository.ListForTenantAsync(query.TenantId, ct);
        return new ListRolesResult(
            roles.Select(r => new RoleSummary(r.Id, r.Name, r.Description, r.IsSystemRole)).ToList());
    }
}
