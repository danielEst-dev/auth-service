using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using FluentValidation;

namespace AuthService.Application.Features.Tenants.Queries;

public sealed class GetTenantHandler(ITenantRepository tenantRepository)
    : IQueryHandler<GetTenantQuery, GetTenantResult>
{
    public async Task<GetTenantResult> HandleAsync(GetTenantQuery query, CancellationToken ct = default)
    {
        var tenant = (query.TenantId, query.Slug) switch
        {
            ({ } id, _)       => await tenantRepository.GetByIdAsync(id, ct),
            (null, { } slug)  => await tenantRepository.GetBySlugAsync(slug, ct),
            _                 => throw new ValidationException("Provide either a valid tenant_id or slug.")
        };

        if (tenant is null)
            throw new NotFoundException("Tenant not found.");

        return new GetTenantResult(
            TenantId:               tenant.Id,
            Slug:                   tenant.Slug,
            Name:                   tenant.Name,
            Plan:                   tenant.Plan,
            CustomDomain:           tenant.CustomDomain,
            IsActive:               tenant.IsActive,
            MfaRequired:            tenant.MfaRequired,
            SessionLifetimeMinutes: tenant.SessionLifetimeMinutes,
            CreatedAt:              tenant.CreatedAt,
            UpdatedAt:              tenant.UpdatedAt);
    }
}
