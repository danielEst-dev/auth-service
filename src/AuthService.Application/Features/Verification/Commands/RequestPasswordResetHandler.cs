using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Common.Security;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Verification.Commands;

public sealed class RequestPasswordResetHandler(
    IUserRepository userRepository,
    IVerificationTokenRepository verificationTokenRepository,
    IRateLimiter rateLimiter,
    ILogger<RequestPasswordResetHandler> logger)
    : ICommandHandler<RequestPasswordResetCommand, RequestPasswordResetResult>
{
    private static readonly TimeSpan PasswordResetTokenLifetime = TimeSpan.FromHours(1);
    private const int  ResetRequestLimit   = 3;
    private static readonly TimeSpan ResetRequestWindow = TimeSpan.FromHours(1);

    public async Task<RequestPasswordResetResult> HandleAsync(
        RequestPasswordResetCommand command, CancellationToken ct = default)
    {
        // Every branch returns success so an observer can't distinguish "email known"
        // from "email unknown" or "throttled" — defeats enumeration.
        if (string.IsNullOrWhiteSpace(command.Email))
            return new RequestPasswordResetResult(true);

        var normalizedEmail = command.Email.Trim().ToUpperInvariant();

        var rlKey = $"rl:pwreset:{command.TenantId}:{normalizedEmail}";
        var rl = await rateLimiter.CheckAsync(rlKey, ResetRequestLimit, ResetRequestWindow, ct);
        if (!rl.Allowed)
        {
            logger.LogInformation("Password reset throttled for email in tenant {TenantId}", command.TenantId);
            return new RequestPasswordResetResult(true);
        }

        var user = await userRepository.GetByEmailAsync(command.TenantId, normalizedEmail, ct);
        if (user is null)
        {
            logger.LogDebug("Password reset requested for unknown email in tenant {TenantId}", command.TenantId);
            return new RequestPasswordResetResult(true);
        }

        var rawToken  = OpaqueToken.Generate();
        var tokenHash = OpaqueToken.Hash(rawToken);
        var vToken    = VerificationToken.Create(user.Id, tokenHash, "password_reset", PasswordResetTokenLifetime);
        await verificationTokenRepository.CreateAsync(vToken, ct);

        // TODO (Phase 5): publish PasswordResetRequestedEvent carrying rawToken so the email
        // consumer sends the link. Don't return the token here — it must only reach the user's inbox.
        logger.LogInformation("Password reset token created for user {UserId} in tenant {TenantId}",
            user.Id, command.TenantId);

        return new RequestPasswordResetResult(true);
    }
}
