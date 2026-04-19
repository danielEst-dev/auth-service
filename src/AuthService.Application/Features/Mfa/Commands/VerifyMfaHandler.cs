using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Mfa.Services;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Mfa.Commands;

public sealed class VerifyMfaHandler(
    IUserRepository userRepository,
    IMfaRepository mfaRepository,
    IMfaVerificationService mfaVerification,
    IMfaRecoveryCodeGenerator recoveryCodes,
    IDomainEventDispatcher eventDispatcher,
    IRateLimiter rateLimiter,
    ILogger<VerifyMfaHandler> logger)
    : ICommandHandler<VerifyMfaCommand, VerifyMfaResult>
{
    private const int VerifyAttemptLimit = 5;
    private static readonly TimeSpan VerifyWindow = TimeSpan.FromMinutes(5);

    public async Task<VerifyMfaResult> HandleAsync(VerifyMfaCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.Code))
            throw new ValidationException("Code is required.");

        var rl = await rateLimiter.CheckAsync(
            $"rl:mfa-verify:{command.UserId}", VerifyAttemptLimit, VerifyWindow, ct);
        if (!rl.Allowed) throw new RateLimitedException(rl.RetryAfter);

        var secret = await mfaRepository.GetSecretByUserIdAsync(command.UserId, ct);
        if (secret is null)
            throw new AuthorizationException("MFA is not set up for this user.");

        var user = await userRepository.GetByIdAsync(command.TenantId, command.UserId, ct)
            ?? throw new NotFoundException("User not found.");

        var codeValid = await mfaVerification.VerifyAsync(command.UserId, command.Code, ct);
        if (!codeValid)
            return new VerifyMfaResult(Success: false, IsConfirmed: secret.IsConfirmed);

        // First successful verify confirms the pending setup and generates initial recovery codes.
        if (!secret.IsConfirmed)
        {
            secret.Confirm();
            await mfaRepository.UpdateSecretAsync(secret, ct);

            user.EnableMfa(secret.Method);
            await userRepository.UpdateAsync(user, ct);

            await recoveryCodes.RegenerateAsync(command.UserId, ct);
            await eventDispatcher.DispatchAndClearAsync(user, ct);

            logger.LogInformation("MFA confirmed for user {UserId} in tenant {TenantId}",
                command.UserId, command.TenantId);
        }

        return new VerifyMfaResult(Success: true, IsConfirmed: true);
    }
}

