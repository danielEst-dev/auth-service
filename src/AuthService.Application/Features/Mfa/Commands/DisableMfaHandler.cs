using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Mfa.Commands;

public sealed class DisableMfaHandler(
    IUserRepository userRepository,
    IMfaRepository mfaRepository,
    IMfaVerificationService mfaVerification,
    ILogger<DisableMfaHandler> logger)
    : ICommandHandler<DisableMfaCommand, DisableMfaResult>
{
    public async Task<DisableMfaResult> HandleAsync(DisableMfaCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.Code))
            throw new FluentValidation.ValidationException("Code is required to confirm disable.");

        var secret = await mfaRepository.GetSecretByUserIdAsync(command.UserId, ct);
        if (secret is null)
            throw new AuthorizationException("MFA is not enabled.");

        if (!await mfaVerification.VerifyAsync(command.UserId, command.Code, ct))
            throw new AuthenticationException("Invalid code.");

        await mfaRepository.DeleteSecretAsync(command.UserId, ct);
        await mfaRepository.DeleteRecoveryCodesAsync(command.UserId, ct);

        var user = await userRepository.GetByIdAsync(command.TenantId, command.UserId, ct)
            ?? throw new NotFoundException("User not found.");

        user.DisableMfa();
        await userRepository.UpdateAsync(user, ct);

        logger.LogInformation("MFA disabled for user {UserId} in tenant {TenantId}",
            command.UserId, command.TenantId);

        return new DisableMfaResult(true);
    }
}
