using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class TenantServiceImpl(
    ITenantRepository tenantRepository,
    ILogger<TenantServiceImpl> logger)
    : TenantService.TenantServiceBase
{
    public override async Task<CreateTenantResponse> CreateTenant(
        CreateTenantRequest request,
        ServerCallContext context)
    {
        if (string.IsNullOrWhiteSpace(request.Slug))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Slug is required."));

        if (string.IsNullOrWhiteSpace(request.Name))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Name is required."));

        var existing = await tenantRepository.GetBySlugAsync(request.Slug, context.CancellationToken);
        if (existing is not null)
            throw new RpcException(new Status(StatusCode.AlreadyExists,
                $"Tenant with slug '{request.Slug}' already exists."));

        var tenant = Tenant.Create(
            slug: request.Slug,
            name: request.Name,
            plan: string.IsNullOrWhiteSpace(request.Plan) ? "free" : request.Plan);

        await tenantRepository.CreateAsync(tenant, context.CancellationToken);

        logger.LogInformation("Tenant {TenantId} ({Slug}) created", tenant.Id, tenant.Slug);

        return new CreateTenantResponse
        {
            TenantId  = tenant.Id.ToString(),
            Slug      = tenant.Slug,
            Name      = tenant.Name,
            Plan      = tenant.Plan,
            CreatedAt = tenant.CreatedAt.ToUnixTimeSeconds()
        };
    }

    public override async Task<GetTenantResponse> GetTenant(
        GetTenantRequest request,
        ServerCallContext context)
    {
        Tenant? tenant = request.LookupCase switch
        {
            GetTenantRequest.LookupOneofCase.TenantId when Guid.TryParse(request.TenantId, out var id)
                => await tenantRepository.GetByIdAsync(id, context.CancellationToken),

            GetTenantRequest.LookupOneofCase.Slug
                => await tenantRepository.GetBySlugAsync(request.Slug, context.CancellationToken),

            _ => throw new RpcException(new Status(StatusCode.InvalidArgument,
                    "Provide either a valid tenant_id or slug."))
        };

        if (tenant is null)
            throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        return new GetTenantResponse
        {
            TenantId               = tenant.Id.ToString(),
            Slug                   = tenant.Slug,
            Name                   = tenant.Name,
            Plan                   = tenant.Plan,
            CustomDomain           = tenant.CustomDomain ?? string.Empty,
            IsActive               = tenant.IsActive,
            MfaRequired            = tenant.MfaRequired,
            SessionLifetimeMinutes = tenant.SessionLifetimeMinutes,
            CreatedAt              = tenant.CreatedAt.ToUnixTimeSeconds(),
            UpdatedAt              = tenant.UpdatedAt.ToUnixTimeSeconds()
        };
    }

    public override async Task<UpdateTenantResponse> UpdateTenant(
        UpdateTenantRequest request,
        ServerCallContext context)
    {
        if (!Guid.TryParse(request.TenantId, out var tenantId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid tenant ID."));

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        if (!string.IsNullOrWhiteSpace(request.Name))
            tenant.UpdateName(request.Name);

        tenant.SetCustomDomain(string.IsNullOrWhiteSpace(request.CustomDomain)
            ? null : request.CustomDomain);

        tenant.RequireMfa(request.MfaRequired);

        await tenantRepository.UpdateAsync(tenant, context.CancellationToken);

        return new UpdateTenantResponse
        {
            Success   = true,
            UpdatedAt = tenant.UpdatedAt.ToUnixTimeSeconds()
        };
    }

    public override async Task<DeactivateTenantResponse> DeactivateTenant(
        DeactivateTenantRequest request,
        ServerCallContext context)
    {
        if (!Guid.TryParse(request.TenantId, out var tenantId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid tenant ID."));

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        tenant.Deactivate();
        await tenantRepository.UpdateAsync(tenant, context.CancellationToken);

        logger.LogInformation("Tenant {TenantId} deactivated", tenantId);

        return new DeactivateTenantResponse { Success = true };
    }
}
