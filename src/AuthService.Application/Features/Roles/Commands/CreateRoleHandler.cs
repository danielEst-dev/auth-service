using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Roles.Commands;

public sealed class CreateRoleHandler(
    IRoleRepository roleRepository,
    ILogger<CreateRoleHandler> logger)
    : ICommandHandler<CreateRoleCommand, CreateRoleResult>
{
    public async Task<CreateRoleResult> HandleAsync(CreateRoleCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.Name))
            throw new ValidationException("Role name is required.");

        var existing = await roleRepository.GetByNameAsync(command.TenantId, command.Name.ToUpperInvariant(), ct);
        if (existing is not null)
            throw new ConflictException($"Role '{command.Name}' already exists in this tenant.");

        var role = Role.CreateTenantRole(
            tenantId:    command.TenantId,
            name:        command.Name,
            description: string.IsNullOrWhiteSpace(command.Description) ? null : command.Description);

        await roleRepository.CreateAsync(role, ct);

        logger.LogInformation("Role {RoleId} ({Name}) created in tenant {TenantId}",
            role.Id, role.Name, command.TenantId);

        return new CreateRoleResult(role.Id, command.TenantId, role.Name, role.CreatedAt);
    }
}
