using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Roles.Commands;

public sealed class UnassignRoleHandler(
    IRoleRepository roleRepository,
    IPermissionCacheService permissionCache,
    ILogger<UnassignRoleHandler> logger)
    : ICommandHandler<UnassignRoleCommand, UnassignRoleResult>
{
    public async Task<UnassignRoleResult> HandleAsync(UnassignRoleCommand command, CancellationToken ct = default)
    {
        await roleRepository.UnassignRoleAsync(command.TenantId, command.UserId, command.RoleId, ct);
        await permissionCache.InvalidatePermissionsAsync(command.TenantId, command.UserId, ct);

        logger.LogInformation("Role {RoleId} unassigned from user {UserId} in tenant {TenantId}",
            command.RoleId, command.UserId, command.TenantId);

        return new UnassignRoleResult(true);
    }
}
