using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Common.Security;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Verification.Commands;

public sealed class VerifyEmailHandler(
    IUserRepository userRepository,
    IVerificationTokenRepository verificationTokenRepository,
    IRateLimiter rateLimiter,
    ILogger<VerifyEmailHandler> logger)
    : ICommandHandler<VerifyEmailCommand, VerifyEmailResult>
{
    private const int TokenSubmitLimit = 10;
    private static readonly TimeSpan TokenSubmitWindow = TimeSpan.FromMinutes(10);

    public async Task<VerifyEmailResult> HandleAsync(VerifyEmailCommand command, CancellationToken ct = default)
    {
        await VerificationRateLimits.EnforceAsync(rateLimiter, command.TenantId, command.PeerIp,
            TokenSubmitLimit, TokenSubmitWindow, ct);

        if (string.IsNullOrWhiteSpace(command.Token))
            throw new ValidationException("Token is required.");

        var tokenHash = OpaqueToken.Hash(command.Token);
        var token = await verificationTokenRepository.GetByTokenHashAsync(tokenHash, ct);

        if (token is null || !token.IsValid || token.Purpose != "email_confirmation")
            throw new NotFoundException("Token is invalid or expired.");

        // Tenant-scoped user read — a token for the wrong tenant yields a clean NotFound
        // (RLS returns null) rather than leaking that the token exists elsewhere.
        var user = await userRepository.GetByIdAsync(command.TenantId, token.UserId, ct)
            ?? throw new NotFoundException("Token is invalid or expired.");

        await verificationTokenRepository.MarkUsedAsync(token.Id, ct);

        user.ConfirmEmail();
        await userRepository.UpdateAsync(user, ct);

        logger.LogInformation("Email confirmed for user {UserId} in tenant {TenantId}", user.Id, command.TenantId);
        return new VerifyEmailResult(true);
    }
}
