using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

/// <summary>
/// Email verification and password reset. Callers MUST supply tenant context via
/// x-tenant-id (typically derived from the subdomain in the email link). Tokens are
/// looked up by hash (not tenant-scoped) but the subsequent user read is RLS-scoped,
/// so a token for the wrong tenant yields NotFound instead of leaking data.
/// </summary>
public sealed class VerificationServiceImpl(
    IUserRepository userRepository,
    IVerificationTokenRepository verificationTokenRepository,
    IPasswordHasher passwordHasher,
    IRateLimiter rateLimiter,
    ILogger<VerificationServiceImpl> logger)
    : VerificationService.VerificationServiceBase
{
    private static readonly TimeSpan PasswordResetTokenLifetime = TimeSpan.FromHours(1);

    // Abuse limits. Tight on password-reset to prevent enumeration/flooding; looser on
    // token submission since legitimate users may click a stale link a few times.
    private const int  ResetRequestLimit   = 3;                 // per {tenant}:{email} per hour
    private const int  TokenSubmitLimit    = 10;                // per {tenant}:{ip} per 10 min
    private static readonly TimeSpan ResetRequestWindow = TimeSpan.FromHours(1);
    private static readonly TimeSpan TokenSubmitWindow  = TimeSpan.FromMinutes(10);

    // ── VerifyEmail ───────────────────────────────────────────────────────────

    public override async Task<VerifyEmailResponse> VerifyEmail(
        VerifyEmailRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        await EnforceTokenSubmitLimitAsync(tenantId, context);

        if (string.IsNullOrWhiteSpace(request.Token))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Token is required."));

        var tokenHash = HashToken(request.Token);
        var token     = await verificationTokenRepository.GetByTokenHashAsync(tokenHash, context.CancellationToken);

        if (token is null || !token.IsValid || token.Purpose != "email_confirmation")
            throw new RpcException(new Status(StatusCode.NotFound, "Token is invalid or expired."));

        // Tenant-scoped user read — if the token's user belongs to a different tenant,
        // RLS returns null and we report NotFound (no cross-tenant leak).
        var user = await userRepository.GetByIdAsync(tenantId, token.UserId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Token is invalid or expired."));

        await verificationTokenRepository.MarkUsedAsync(token.Id, context.CancellationToken);

        user.ConfirmEmail();
        await userRepository.UpdateAsync(user, context.CancellationToken);

        logger.LogInformation("Email confirmed for user {UserId} in tenant {TenantId}", user.Id, tenantId);

        return new VerifyEmailResponse { Success = true };
    }

    // ── RequestPasswordReset ──────────────────────────────────────────────────

    public override async Task<RequestPasswordResetResponse> RequestPasswordReset(
        RequestPasswordResetRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        // Always return success — prevents email enumeration
        if (string.IsNullOrWhiteSpace(request.Email))
            return new RequestPasswordResetResponse { Success = true };

        var normalizedEmail = request.Email.Trim().ToUpperInvariant();

        // Rate-limit by {tenant}:{email} so an attacker can't enumerate or flood one account.
        var rlKey = $"rl:pwreset:{tenantId}:{normalizedEmail}";
        var rl    = await rateLimiter.CheckAsync(rlKey, ResetRequestLimit, ResetRequestWindow, context.CancellationToken);
        if (!rl.Allowed)
        {
            logger.LogInformation("Password reset throttled for {Email} in tenant {TenantId}", normalizedEmail, tenantId);
            return new RequestPasswordResetResponse { Success = true }; // silent — no enumeration signal
        }

        var user = await userRepository.GetByEmailAsync(tenantId, normalizedEmail, context.CancellationToken);
        if (user is null)
        {
            logger.LogDebug("Password reset requested for unknown email in tenant {TenantId}", tenantId);
            return new RequestPasswordResetResponse { Success = true };
        }

        var rawToken  = GenerateRawToken();
        var tokenHash = HashToken(rawToken);
        var vToken    = VerificationToken.Create(user.Id, tokenHash, "password_reset", PasswordResetTokenLifetime);

        await verificationTokenRepository.CreateAsync(vToken, context.CancellationToken);

        // TODO (Phase 5): publish PasswordResetRequestedEvent with rawToken so the email consumer sends the link
        logger.LogInformation("Password reset token created for user {UserId} in tenant {TenantId}", user.Id, tenantId);

        return new RequestPasswordResetResponse { Success = true };
    }

    // ── ResetPassword ─────────────────────────────────────────────────────────

    public override async Task<ResetPasswordResponse> ResetPassword(
        ResetPasswordRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        await EnforceTokenSubmitLimitAsync(tenantId, context);

        if (string.IsNullOrWhiteSpace(request.Token))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Token is required."));

        if (string.IsNullOrWhiteSpace(request.NewPassword) || request.NewPassword.Length < 8)
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "New password must be at least 8 characters."));

        var tokenHash = HashToken(request.Token);
        var token     = await verificationTokenRepository.GetByTokenHashAsync(tokenHash, context.CancellationToken);

        if (token is null || !token.IsValid || token.Purpose != "password_reset")
            throw new RpcException(new Status(StatusCode.NotFound, "Token is invalid or expired."));

        var user = await userRepository.GetByIdAsync(tenantId, token.UserId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Token is invalid or expired."));

        await verificationTokenRepository.MarkUsedAsync(token.Id, context.CancellationToken);

        user.SetPasswordHash(passwordHasher.Hash(request.NewPassword));
        await userRepository.UpdateAsync(user, context.CancellationToken);

        logger.LogInformation("Password reset for user {UserId} in tenant {TenantId}", user.Id, tenantId);

        return new ResetPasswordResponse { Success = true };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task EnforceTokenSubmitLimitAsync(Guid tenantId, ServerCallContext context)
    {
        var ip = ExtractPeerIp(context);
        var key = $"rl:vtoken:{tenantId}:{ip}";
        var rl = await rateLimiter.CheckAsync(key, TokenSubmitLimit, TokenSubmitWindow, context.CancellationToken);
        if (!rl.Allowed)
            throw new RpcException(new Status(StatusCode.ResourceExhausted,
                $"Too many verification attempts. Try again in {(int)rl.RetryAfter.TotalSeconds} s."));
    }

    private static string ExtractPeerIp(ServerCallContext context)
    {
        // context.Peer is like "ipv4:127.0.0.1:54321" — strip the port/scheme for the key.
        var peer = context.Peer ?? "unknown";
        var colon = peer.LastIndexOf(':');
        return colon > 0 ? peer[..colon] : peer;
    }

    private static string HashToken(string rawToken)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(rawToken);
        var hash  = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string GenerateRawToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }
}
