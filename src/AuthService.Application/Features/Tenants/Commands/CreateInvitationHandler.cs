using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Common.Security;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Tenants.Commands;

public sealed class CreateInvitationHandler(
    ITenantInvitationRepository invitationRepository,
    ILogger<CreateInvitationHandler> logger)
    : ICommandHandler<CreateInvitationCommand, CreateInvitationResult>
{
    public async Task<CreateInvitationResult> HandleAsync(CreateInvitationCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.Email))
            throw new ValidationException("Email is required.");

        if (await invitationRepository.ExistsForEmailAsync(command.TenantId, command.Email, ct))
            throw new ConflictException("An active invitation already exists for this email.");

        var rawToken  = OpaqueToken.Generate();
        var tokenHash = OpaqueToken.Hash(rawToken);
        var invitation = TenantInvitation.Create(command.TenantId, command.Email, tokenHash, command.RoleId);

        await invitationRepository.CreateAsync(invitation, ct);

        logger.LogInformation("Invitation {InvitationId} created for {Email} in tenant {TenantId}",
            invitation.Id, command.Email, command.TenantId);

        // TODO (Phase 5): publish InvitationCreatedEvent so an email consumer sends the link.
        return new CreateInvitationResult(invitation.Id, rawToken, invitation.ExpiresAt);
    }
}
