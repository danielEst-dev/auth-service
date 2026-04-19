using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Tenants.Commands;

public sealed class DeactivateTenantHandler(
    ITenantRepository tenantRepository,
    ILogger<DeactivateTenantHandler> logger)
    : ICommandHandler<DeactivateTenantCommand, DeactivateTenantResult>
{
    public async Task<DeactivateTenantResult> HandleAsync(DeactivateTenantCommand command, CancellationToken ct = default)
    {
        var tenant = await tenantRepository.GetByIdAsync(command.TenantId, ct)
            ?? throw new NotFoundException("Tenant not found.");

        tenant.Deactivate();
        await tenantRepository.UpdateAsync(tenant, ct);
        logger.LogInformation("Tenant {TenantId} deactivated", command.TenantId);

        return new DeactivateTenantResult(true);
    }
}
