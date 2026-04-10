using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class RoleServiceImpl(
    IRoleRepository roleRepository,
    ILogger<RoleServiceImpl> logger)
    : RoleService.RoleServiceBase
{
    // ── CreateRole ────────────────────────────────────────────────────────────

    public override async Task<CreateRoleResponse> CreateRole(
        CreateRoleRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (string.IsNullOrWhiteSpace(request.Name))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Role name is required."));

        var existing = await roleRepository.GetByNameAsync(
            tenantId, request.Name.ToUpperInvariant(), context.CancellationToken);

        if (existing is not null)
            throw new RpcException(new Status(StatusCode.AlreadyExists,
                $"Role '{request.Name}' already exists in this tenant."));

        var role = Role.CreateTenantRole(
            tenantId:    tenantId,
            name:        request.Name,
            description: string.IsNullOrWhiteSpace(request.Description) ? null : request.Description);

        await roleRepository.CreateAsync(role, context.CancellationToken);

        logger.LogInformation("Role {RoleId} ({Name}) created in tenant {TenantId}",
            role.Id, role.Name, tenantId);

        return new CreateRoleResponse
        {
            RoleId    = role.Id.ToString(),
            TenantId  = tenantId.ToString(),
            Name      = role.Name,
            CreatedAt = role.CreatedAt.ToUnixTimeSeconds()
        };
    }

    // ── AssignRole ────────────────────────────────────────────────────────────

    public override async Task<AssignRoleResponse> AssignRole(
        AssignRoleRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        if (!Guid.TryParse(request.RoleId, out var roleId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid role ID."));

        Guid? assignedBy = Guid.TryParse(request.AssignedBy, out var ab) ? ab : null;

        var role = await roleRepository.GetByIdAsync(tenantId, roleId, context.CancellationToken);
        if (role is null)
            throw new RpcException(new Status(StatusCode.NotFound,
                $"Role '{roleId}' not found in this tenant."));

        await roleRepository.AssignRoleAsync(tenantId, userId, roleId, assignedBy,
            context.CancellationToken);

        logger.LogInformation("Role {RoleId} assigned to user {UserId} in tenant {TenantId}",
            roleId, userId, tenantId);

        return new AssignRoleResponse { Success = true };
    }

    // ── UnassignRole ──────────────────────────────────────────────────────────

    public override async Task<UnassignRoleResponse> UnassignRole(
        UnassignRoleRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        if (!Guid.TryParse(request.RoleId, out var roleId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid role ID."));

        await roleRepository.UnassignRoleAsync(tenantId, userId, roleId, context.CancellationToken);

        logger.LogInformation("Role {RoleId} unassigned from user {UserId} in tenant {TenantId}",
            roleId, userId, tenantId);

        return new UnassignRoleResponse { Success = true };
    }

    // ── GetPermissions ────────────────────────────────────────────────────────

    public override async Task<GetPermissionsResponse> GetPermissions(
        GetPermissionsRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        var roles       = await roleRepository.GetRoleNamesForUserAsync(tenantId, userId, context.CancellationToken);
        var permissions = await roleRepository.GetPermissionNamesForUserAsync(tenantId, userId, context.CancellationToken);

        var response = new GetPermissionsResponse();
        response.Roles.AddRange(roles);
        response.Permissions.AddRange(permissions);
        return response;
    }

    // ── ListRoles ─────────────────────────────────────────────────────────────

    public override async Task<ListRolesResponse> ListRoles(
        ListRolesRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);
        var roles = await roleRepository.ListForTenantAsync(tenantId, context.CancellationToken);

        var response = new ListRolesResponse();
        response.Roles.AddRange(roles.Select(r => new RoleInfo
        {
            RoleId       = r.Id.ToString(),
            Name         = r.Name,
            Description  = r.Description ?? string.Empty,
            IsSystemRole = r.IsSystemRole
        }));
        return response;
    }

}
