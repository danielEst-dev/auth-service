using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Mfa.Services;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Mfa.Commands;

public sealed class GenerateRecoveryCodesHandler(
    IUserRepository userRepository,
    IMfaRecoveryCodeGenerator recoveryCodes,
    ILogger<GenerateRecoveryCodesHandler> logger)
    : ICommandHandler<GenerateRecoveryCodesCommand, GenerateRecoveryCodesResult>
{
    public async Task<GenerateRecoveryCodesResult> HandleAsync(
        GenerateRecoveryCodesCommand command, CancellationToken ct = default)
    {
        var user = await userRepository.GetByIdAsync(command.TenantId, command.UserId, ct)
            ?? throw new NotFoundException("User not found.");

        if (!user.MfaEnabled)
            throw new AuthorizationException("MFA must be enabled before generating recovery codes.");

        var plainCodes = await recoveryCodes.RegenerateAsync(command.UserId, ct);

        logger.LogInformation("Recovery codes regenerated for user {UserId} in tenant {TenantId}",
            command.UserId, command.TenantId);

        return new GenerateRecoveryCodesResult(plainCodes);
    }
}
