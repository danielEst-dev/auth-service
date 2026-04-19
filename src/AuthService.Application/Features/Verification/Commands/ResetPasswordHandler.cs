using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Common.Security;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Verification.Commands;

public sealed class ResetPasswordHandler(
    IUserRepository userRepository,
    IVerificationTokenRepository verificationTokenRepository,
    IPasswordHasher passwordHasher,
    IRateLimiter rateLimiter,
    ILogger<ResetPasswordHandler> logger)
    : ICommandHandler<ResetPasswordCommand, ResetPasswordResult>
{
    private const int  TokenSubmitLimit    = 10;
    private static readonly TimeSpan TokenSubmitWindow = TimeSpan.FromMinutes(10);

    public async Task<ResetPasswordResult> HandleAsync(ResetPasswordCommand command, CancellationToken ct = default)
    {
        await VerificationRateLimits.EnforceAsync(rateLimiter, command.TenantId, command.PeerIp,
            TokenSubmitLimit, TokenSubmitWindow, ct);

        if (string.IsNullOrWhiteSpace(command.Token))
            throw new ValidationException("Token is required.");
        if (string.IsNullOrWhiteSpace(command.NewPassword) || command.NewPassword.Length < 8)
            throw new ValidationException("New password must be at least 8 characters.");

        var tokenHash = OpaqueToken.Hash(command.Token);
        var token = await verificationTokenRepository.GetByTokenHashAsync(tokenHash, ct);

        if (token is null || !token.IsValid || token.Purpose != "password_reset")
            throw new NotFoundException("Token is invalid or expired.");

        var user = await userRepository.GetByIdAsync(command.TenantId, token.UserId, ct)
            ?? throw new NotFoundException("Token is invalid or expired.");

        await verificationTokenRepository.MarkUsedAsync(token.Id, ct);

        user.SetPasswordHash(passwordHasher.Hash(command.NewPassword));
        await userRepository.UpdateAsync(user, ct);

        logger.LogInformation("Password reset for user {UserId} in tenant {TenantId}", user.Id, command.TenantId);
        return new ResetPasswordResult(true);
    }
}
