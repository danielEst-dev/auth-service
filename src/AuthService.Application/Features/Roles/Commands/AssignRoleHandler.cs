using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Domain.Events;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Roles.Commands;

public sealed class AssignRoleHandler(
    IRoleRepository roleRepository,
    IPermissionCacheService permissionCache,
    IEventPublisher eventPublisher,
    ILogger<AssignRoleHandler> logger)
    : ICommandHandler<AssignRoleCommand, AssignRoleResult>
{
    public async Task<AssignRoleResult> HandleAsync(AssignRoleCommand command, CancellationToken ct = default)
    {
        var role = await roleRepository.GetByIdAsync(command.TenantId, command.RoleId, ct)
            ?? throw new NotFoundException($"Role '{command.RoleId}' not found in this tenant.");

        await roleRepository.AssignRoleAsync(command.TenantId, command.UserId, command.RoleId, command.AssignedBy, ct);

        // Invalidate cached permissions so the next request reflects the new role.
        await permissionCache.InvalidatePermissionsAsync(command.TenantId, command.UserId, ct);

        logger.LogInformation("Role {RoleId} assigned to user {UserId} in tenant {TenantId}",
            command.RoleId, command.UserId, command.TenantId);

        await eventPublisher.PublishAsync(
            new RoleAssignedEvent(command.UserId, command.TenantId, command.RoleId, role.Name), ct);

        return new AssignRoleResult(true);
    }
}
