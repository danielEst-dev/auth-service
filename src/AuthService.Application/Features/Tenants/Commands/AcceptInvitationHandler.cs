using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Common.Security;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Tenants.Commands;

public sealed class AcceptInvitationHandler(
    ITenantInvitationRepository invitationRepository,
    ITenantRepository tenantRepository,
    IUserRepository userRepository,
    IRoleRepository roleRepository,
    IPasswordHasher passwordHasher,
    IDomainEventDispatcher eventDispatcher,
    ILogger<AcceptInvitationHandler> logger)
    : ICommandHandler<AcceptInvitationCommand, AcceptInvitationResult>
{
    public async Task<AcceptInvitationResult> HandleAsync(AcceptInvitationCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.Token))
            throw new ValidationException("Token is required.");
        if (string.IsNullOrWhiteSpace(command.Password) || command.Password.Length < 8)
            throw new ValidationException("Password must be at least 8 characters.");
        if (string.IsNullOrWhiteSpace(command.Username))
            throw new ValidationException("Username is required.");

        var tokenHash = OpaqueToken.Hash(command.Token);
        var invitation = await invitationRepository.GetByTokenHashAsync(tokenHash, ct)
            ?? throw new NotFoundException("Invitation not found.");

        if (invitation.IsAccepted)
            throw new AuthorizationException("Invitation has already been accepted.");
        if (invitation.IsExpired)
            throw new AuthorizationException("Invitation has expired.");

        // Pre-flight: tenant must exist (could have been deleted between invite and accept)
        _ = await tenantRepository.GetByIdAsync(invitation.TenantId, ct)
            ?? throw new NotFoundException("Tenant not found.");

        var user = User.CreateFromInvitation(
            invitationId: invitation.Id,
            tenantId:     invitation.TenantId,
            email:        invitation.Email,
            username:     command.Username,
            passwordHash: passwordHasher.Hash(command.Password));

        await userRepository.CreateAsync(user, ct);

        if (invitation.RoleId.HasValue)
            await roleRepository.AssignRoleAsync(invitation.TenantId, user.Id, invitation.RoleId.Value, null, ct);

        invitation.Accept();
        await invitationRepository.UpdateAsync(invitation, ct);

        await eventDispatcher.DispatchAndClearAsync(user, ct);

        logger.LogInformation(
            "Invitation {InvitationId} accepted — user {UserId} created in tenant {TenantId}",
            invitation.Id, user.Id, invitation.TenantId);

        return new AcceptInvitationResult(user.Id, invitation.TenantId, invitation.Email);
    }
}
