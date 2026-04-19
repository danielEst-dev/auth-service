using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Roles.Commands;
using AuthService.Application.Features.Roles.Queries;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class RoleServiceImpl(
    ICommandHandler<CreateRoleCommand,   CreateRoleResult>     createRole,
    ICommandHandler<AssignRoleCommand,   AssignRoleResult>     assignRole,
    ICommandHandler<UnassignRoleCommand, UnassignRoleResult>   unassignRole,
    IQueryHandler<GetPermissionsQuery,   GetPermissionsResult> getPermissions,
    IQueryHandler<ListRolesQuery,        ListRolesResult>      listRoles)
    : RoleService.RoleServiceBase
{
    public override async Task<CreateRoleResponse> CreateRole(CreateRoleRequest request, ServerCallContext context)
    {
        var result = await createRole.HandleAsync(
            new CreateRoleCommand(
                TenantId:    GrpcTenantHelper.GetRequiredTenantId(context),
                Name:        request.Name,
                Description: request.Description),
            context.CancellationToken);

        return new CreateRoleResponse
        {
            RoleId    = result.RoleId.ToString(),
            TenantId  = result.TenantId.ToString(),
            Name      = result.Name,
            CreatedAt = result.CreatedAt.ToUnixTimeSeconds(),
        };
    }

    public override async Task<AssignRoleResponse> AssignRole(AssignRoleRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));
        if (!Guid.TryParse(request.RoleId, out var roleId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid role ID."));

        Guid? assignedBy = Guid.TryParse(request.AssignedBy, out var ab) ? ab : null;

        var result = await assignRole.HandleAsync(
            new AssignRoleCommand(
                TenantId:   GrpcTenantHelper.GetRequiredTenantId(context),
                UserId:     userId,
                RoleId:     roleId,
                AssignedBy: assignedBy),
            context.CancellationToken);

        return new AssignRoleResponse { Success = result.Success };
    }

    public override async Task<UnassignRoleResponse> UnassignRole(UnassignRoleRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));
        if (!Guid.TryParse(request.RoleId, out var roleId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid role ID."));

        var result = await unassignRole.HandleAsync(
            new UnassignRoleCommand(
                TenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                UserId:   userId,
                RoleId:   roleId),
            context.CancellationToken);

        return new UnassignRoleResponse { Success = result.Success };
    }

    public override async Task<GetPermissionsResponse> GetPermissions(
        GetPermissionsRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        var result = await getPermissions.HandleAsync(
            new GetPermissionsQuery(GrpcTenantHelper.GetRequiredTenantId(context), userId),
            context.CancellationToken);

        var response = new GetPermissionsResponse();
        response.Roles.AddRange(result.Roles);
        response.Permissions.AddRange(result.Permissions);
        return response;
    }

    public override async Task<ListRolesResponse> ListRoles(ListRolesRequest request, ServerCallContext context)
    {
        var result = await listRoles.HandleAsync(
            new ListRolesQuery(GrpcTenantHelper.GetRequiredTenantId(context)),
            context.CancellationToken);

        var response = new ListRolesResponse();
        response.Roles.AddRange(result.Roles.Select(r => new RoleInfo
        {
            RoleId       = r.RoleId.ToString(),
            Name         = r.Name,
            Description  = r.Description ?? string.Empty,
            IsSystemRole = r.IsSystemRole,
        }));
        return response;
    }
}
