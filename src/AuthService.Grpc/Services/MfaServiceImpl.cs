using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;
using Microsoft.Extensions.Configuration;

namespace AuthService.Grpc.Services;

public sealed class MfaServiceImpl(
    IUserRepository userRepository,
    IMfaRepository mfaRepository,
    ITotpService totpService,
    ISecretProtector secretProtector,
    IMfaVerificationService mfaVerification,
    IPasswordHasher passwordHasher,
    IRateLimiter rateLimiter,
    IDomainEventDispatcher eventDispatcher,
    IConfiguration configuration,
    ILogger<MfaServiceImpl> logger)
    : MfaService.MfaServiceBase
{
    private const int RecoveryCodeCount = 8;
    private const int RecoveryCodeLength = 8;
    private const string RecoveryCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous 0/O, 1/I

    private const int VerifyAttemptLimit = 5;
    private static readonly TimeSpan VerifyWindow = TimeSpan.FromMinutes(5);

    private string Issuer => configuration["Jwt:Issuer"] ?? "AuthService";

    // ── EnableMfa ─────────────────────────────────────────────────────────────

    public override async Task<EnableMfaResponse> EnableMfa(
        EnableMfaRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        var user = await userRepository.GetByIdAsync(tenantId, userId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found."));

        var plainSecret = totpService.GenerateSecret();
        var qrCodeUri   = totpService.GenerateQrCodeUri(Issuer, user.Email, plainSecret);

        // Store encrypted — confirmed on first successful VerifyMfa call
        var mfaSecret = MfaSecret.Create(userId, secretProtector.Protect(plainSecret));
        await mfaRepository.CreateSecretAsync(mfaSecret, context.CancellationToken);

        logger.LogInformation("MFA setup initiated for user {UserId} in tenant {TenantId}", userId, tenantId);

        // QR URI is shown to the user ONCE — the plaintext secret never leaves this response
        return new EnableMfaResponse { Secret = plainSecret, QrCodeUri = qrCodeUri };
    }

    // ── VerifyMfa ─────────────────────────────────────────────────────────────

    public override async Task<VerifyMfaResponse> VerifyMfa(
        VerifyMfaRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        if (string.IsNullOrWhiteSpace(request.Code))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Code is required."));

        // Rate-limit by userId: 5 attempts / 5 min ≈ 1-in-200k TOTP brute force.
        var rl = await rateLimiter.CheckAsync(
            $"rl:mfa-verify:{userId}", VerifyAttemptLimit, VerifyWindow, context.CancellationToken);
        if (!rl.Allowed)
            throw new RpcException(new Status(StatusCode.ResourceExhausted,
                $"Too many MFA attempts. Try again in {(int)rl.RetryAfter.TotalSeconds} s."));

        var mfaSecret = await mfaRepository.GetSecretByUserIdAsync(userId, context.CancellationToken);
        if (mfaSecret is null)
            throw new RpcException(new Status(StatusCode.FailedPrecondition,
                "MFA is not set up for this user."));

        var user = await userRepository.GetByIdAsync(tenantId, userId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found."));

        var codeVerified = await mfaVerification.VerifyAsync(userId, request.Code, context.CancellationToken);
        if (!codeVerified)
            return new VerifyMfaResponse { Success = false, IsConfirmed = mfaSecret.IsConfirmed };

        var wasAlreadyConfirmed = mfaSecret.IsConfirmed;

        if (!wasAlreadyConfirmed)
        {
            mfaSecret.Confirm();
            await mfaRepository.UpdateSecretAsync(mfaSecret, context.CancellationToken);

            user.EnableMfa(mfaSecret.Method);
            await userRepository.UpdateAsync(user, context.CancellationToken);

            // Generate initial recovery codes on first confirmation
            await GenerateAndStoreRecoveryCodesAsync(userId, context.CancellationToken);

            await eventDispatcher.DispatchAndClearAsync(user, context.CancellationToken);

            logger.LogInformation("MFA confirmed for user {UserId} in tenant {TenantId}", userId, tenantId);
        }

        return new VerifyMfaResponse { Success = true, IsConfirmed = true };
    }

    // ── DisableMfa ────────────────────────────────────────────────────────────

    public override async Task<DisableMfaResponse> DisableMfa(
        DisableMfaRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        if (string.IsNullOrWhiteSpace(request.Code))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Code is required to confirm disable."));

        var mfaSecret = await mfaRepository.GetSecretByUserIdAsync(userId, context.CancellationToken);
        if (mfaSecret is null)
            throw new RpcException(new Status(StatusCode.FailedPrecondition, "MFA is not enabled."));

        var codeVerified = await mfaVerification.VerifyAsync(userId, request.Code, context.CancellationToken);
        if (!codeVerified)
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Invalid code."));

        await mfaRepository.DeleteSecretAsync(userId, context.CancellationToken);
        await mfaRepository.DeleteRecoveryCodesAsync(userId, context.CancellationToken);

        var user = await userRepository.GetByIdAsync(tenantId, userId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found."));

        user.DisableMfa();
        await userRepository.UpdateAsync(user, context.CancellationToken);

        logger.LogInformation("MFA disabled for user {UserId} in tenant {TenantId}", userId, tenantId);

        return new DisableMfaResponse { Success = true };
    }

    // ── GenerateRecoveryCodes ─────────────────────────────────────────────────

    public override async Task<GenerateRecoveryCodesResponse> GenerateRecoveryCodes(
        GenerateRecoveryCodesRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        var user = await userRepository.GetByIdAsync(tenantId, userId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found."));

        if (!user.MfaEnabled)
            throw new RpcException(new Status(StatusCode.FailedPrecondition,
                "MFA must be enabled before generating recovery codes."));

        await mfaRepository.DeleteRecoveryCodesAsync(userId, context.CancellationToken);
        var plainCodes = await GenerateAndStoreRecoveryCodesAsync(userId, context.CancellationToken);

        logger.LogInformation("Recovery codes regenerated for user {UserId} in tenant {TenantId}", userId, tenantId);

        var response = new GenerateRecoveryCodesResponse();
        response.Codes.AddRange(plainCodes);
        return response;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task<IReadOnlyList<string>> GenerateAndStoreRecoveryCodesAsync(
        Guid userId, CancellationToken ct)
    {
        var plainCodes = Enumerable.Range(0, RecoveryCodeCount)
            .Select(_ => GenerateSecureRecoveryCode())
            .ToList();

        var entities = plainCodes
            .Select(c => MfaRecoveryCode.Create(userId, passwordHasher.Hash(c)))
            .ToList();

        await mfaRepository.CreateRecoveryCodesAsync(entities, ct);
        return plainCodes;
    }

    private static string GenerateSecureRecoveryCode()
    {
        var buf = new char[RecoveryCodeLength];
        for (var i = 0; i < RecoveryCodeLength; i++)
            buf[i] = RecoveryCodeAlphabet[RandomNumberGenerator.GetInt32(RecoveryCodeAlphabet.Length)];
        return new string(buf);
    }
}
