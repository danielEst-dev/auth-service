using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Tenants.Dtos;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Tenants.Commands;

public sealed class CreateTenantHandler(
    ITenantRepository tenantRepository,
    IDomainEventDispatcher eventDispatcher,
    IValidator<CreateTenantDto> validator,
    ILogger<CreateTenantHandler> logger)
    : ICommandHandler<CreateTenantCommand, CreateTenantResult>
{
    private const string DefaultPlan = "free";

    public async Task<CreateTenantResult> HandleAsync(CreateTenantCommand command, CancellationToken ct = default)
    {
        var plan = string.IsNullOrWhiteSpace(command.Plan) ? DefaultPlan : command.Plan;
        var dto = new CreateTenantDto(command.Slug, command.Name, plan);

        var validation = await validator.ValidateAsync(dto, ct);
        if (!validation.IsValid) throw new ValidationException(validation.Errors);

        if (await tenantRepository.ExistsBySlugAsync(command.Slug, ct))
            throw new ConflictException($"Tenant with slug '{command.Slug}' already exists.");

        var tenant = Tenant.Create(slug: command.Slug, name: command.Name, plan: plan);
        await tenantRepository.CreateAsync(tenant, ct);
        await eventDispatcher.DispatchAndClearAsync(tenant, ct);

        logger.LogInformation("Tenant {TenantId} ({Slug}) created", tenant.Id, tenant.Slug);

        return new CreateTenantResult(tenant.Id, tenant.Slug, tenant.Name, tenant.Plan, tenant.CreatedAt);
    }
}
