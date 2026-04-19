using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Tenants.Commands;
using AuthService.Application.Features.Tenants.Queries;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class TenantServiceImpl(
    ICommandHandler<CreateTenantCommand,     CreateTenantResult>     createTenant,
    IQueryHandler<GetTenantQuery,            GetTenantResult>        getTenant,
    ICommandHandler<UpdateTenantCommand,     UpdateTenantResult>     updateTenant,
    ICommandHandler<DeactivateTenantCommand, DeactivateTenantResult> deactivateTenant,
    ICommandHandler<CreateInvitationCommand, CreateInvitationResult> createInvitation,
    ICommandHandler<AcceptInvitationCommand, AcceptInvitationResult> acceptInvitation)
    : TenantService.TenantServiceBase
{
    public override async Task<CreateTenantResponse> CreateTenant(
        CreateTenantRequest request, ServerCallContext context)
    {
        var result = await createTenant.HandleAsync(
            new CreateTenantCommand(request.Slug, request.Name, request.Plan),
            context.CancellationToken);

        return new CreateTenantResponse
        {
            TenantId  = result.TenantId.ToString(),
            Slug      = result.Slug,
            Name      = result.Name,
            Plan      = result.Plan,
            CreatedAt = result.CreatedAt.ToUnixTimeSeconds(),
        };
    }

    public override async Task<GetTenantResponse> GetTenant(
        GetTenantRequest request, ServerCallContext context)
    {
        var tenantId = request.LookupCase == GetTenantRequest.LookupOneofCase.TenantId
            && Guid.TryParse(request.TenantId, out var parsed) ? parsed : (Guid?)null;
        var slug = request.LookupCase == GetTenantRequest.LookupOneofCase.Slug ? request.Slug : null;

        var result = await getTenant.HandleAsync(new GetTenantQuery(tenantId, slug), context.CancellationToken);

        return new GetTenantResponse
        {
            TenantId               = result.TenantId.ToString(),
            Slug                   = result.Slug,
            Name                   = result.Name,
            Plan                   = result.Plan,
            CustomDomain           = result.CustomDomain ?? string.Empty,
            IsActive               = result.IsActive,
            MfaRequired            = result.MfaRequired,
            SessionLifetimeMinutes = result.SessionLifetimeMinutes,
            CreatedAt              = result.CreatedAt.ToUnixTimeSeconds(),
            UpdatedAt              = result.UpdatedAt.ToUnixTimeSeconds(),
        };
    }

    public override async Task<UpdateTenantResponse> UpdateTenant(
        UpdateTenantRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.TenantId, out var tenantId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid tenant ID."));

        var result = await updateTenant.HandleAsync(
            new UpdateTenantCommand(
                TenantId:               tenantId,
                Name:                   string.IsNullOrWhiteSpace(request.Name) ? null : request.Name,
                CustomDomain:           request.CustomDomain,
                MfaRequired:            request.MfaRequired,
                SessionLifetimeMinutes: request.SessionLifetimeMinutes),
            context.CancellationToken);

        return new UpdateTenantResponse { Success = result.Success, UpdatedAt = result.UpdatedAt.ToUnixTimeSeconds() };
    }

    public override async Task<DeactivateTenantResponse> DeactivateTenant(
        DeactivateTenantRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.TenantId, out var tenantId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid tenant ID."));

        var result = await deactivateTenant.HandleAsync(
            new DeactivateTenantCommand(tenantId), context.CancellationToken);

        return new DeactivateTenantResponse { Success = result.Success };
    }

    public override async Task<CreateInvitationResponse> CreateInvitation(
        CreateInvitationRequest request, ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);
        Guid? roleId = Guid.TryParse(request.RoleId, out var rid) ? rid : null;

        var result = await createInvitation.HandleAsync(
            new CreateInvitationCommand(tenantId, request.Email, roleId),
            context.CancellationToken);

        return new CreateInvitationResponse
        {
            InvitationId = result.InvitationId.ToString(),
            Token        = result.Token,
            ExpiresAt    = result.ExpiresAt.ToUnixTimeSeconds(),
        };
    }

    public override async Task<AcceptInvitationResponse> AcceptInvitation(
        AcceptInvitationRequest request, ServerCallContext context)
    {
        var result = await acceptInvitation.HandleAsync(
            new AcceptInvitationCommand(request.Token, request.Password, request.Username),
            context.CancellationToken);

        return new AcceptInvitationResponse
        {
            UserId   = result.UserId.ToString(),
            TenantId = result.TenantId.ToString(),
            Email    = result.Email,
        };
    }
}
