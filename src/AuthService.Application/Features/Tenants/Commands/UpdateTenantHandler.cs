using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;

namespace AuthService.Application.Features.Tenants.Commands;

public sealed class UpdateTenantHandler(ITenantRepository tenantRepository)
    : ICommandHandler<UpdateTenantCommand, UpdateTenantResult>
{
    public async Task<UpdateTenantResult> HandleAsync(UpdateTenantCommand command, CancellationToken ct = default)
    {
        var tenant = await tenantRepository.GetByIdAsync(command.TenantId, ct)
            ?? throw new NotFoundException("Tenant not found.");

        if (!string.IsNullOrWhiteSpace(command.Name))
            tenant.UpdateName(command.Name);

        tenant.SetCustomDomain(string.IsNullOrWhiteSpace(command.CustomDomain) ? null : command.CustomDomain);
        tenant.RequireMfa(command.MfaRequired);

        if (command.SessionLifetimeMinutes > 0)
            tenant.UpdateSessionLifetime(command.SessionLifetimeMinutes);

        await tenantRepository.UpdateAsync(tenant, ct);
        return new UpdateTenantResult(true, tenant.UpdatedAt);
    }
}
