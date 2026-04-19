using System.Text.Json;
using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Auth.Dtos;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Auth.Commands;

public sealed class CompleteMfaLoginHandler(
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IRoleRepository roleRepository,
    IMfaVerificationService mfaVerification,
    ITokenService tokenService,
    ICacheService cacheService,
    IRateLimiter rateLimiter,
    ILogger<CompleteMfaLoginHandler> logger)
    : ICommandHandler<CompleteMfaLoginCommand, CompleteMfaLoginResult>
{
    private const int MfaAttemptLimit = 5;
    private static readonly TimeSpan MfaWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);

    public async Task<CompleteMfaLoginResult> HandleAsync(
        CompleteMfaLoginCommand command, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(command.MfaPendingToken))
            throw new ValidationException("MFA pending token is required.");
        if (string.IsNullOrWhiteSpace(command.Code))
            throw new ValidationException("Code is required.");

        // Rate-limit by pending token: 5 attempts / 5 min ≈ 1-in-200k TOTP brute force
        var rl = await rateLimiter.CheckAsync(
            $"rl:mfa:{command.MfaPendingToken}", MfaAttemptLimit, MfaWindow, ct);
        if (!rl.Allowed) throw new RateLimitedException(rl.RetryAfter);

        var cacheKey = $"mfa_pending:{command.MfaPendingToken}";
        var json = await cacheService.GetAsync(cacheKey, ct)
            ?? throw new AuthenticationException("MFA pending token is invalid or expired.");

        MfaPendingPayload payload;
        try
        {
            payload = JsonSerializer.Deserialize<MfaPendingPayload>(json)
                ?? throw new InvalidOperationException("Null payload.");
        }
        catch
        {
            throw new AuthenticationException("Invalid MFA session.");
        }

        if (payload.TenantId != command.TenantId)
            throw new AuthenticationException("Tenant mismatch.");

        if (!await mfaVerification.VerifyAsync(payload.UserId, command.Code, ct))
            throw new AuthenticationException("Invalid MFA code.");

        // Single use — consume immediately to prevent replay even if a racing caller
        // somehow validates with the same pending token
        await cacheService.DeleteAsync(cacheKey, ct);

        var user = await userRepository.GetByIdAsync(command.TenantId, payload.UserId, ct)
            ?? throw new NotFoundException("User not found.");
        var tenant = await tenantRepository.GetByIdAsync(command.TenantId, ct)
            ?? throw new NotFoundException("Tenant not found.");

        // Re-fetch roles/permissions at completion so a role revocation during the
        // 5-minute MFA window is respected
        var roles       = await roleRepository.GetRoleNamesForUserAsync(command.TenantId, user.Id, ct);
        var permissions = await roleRepository.GetPermissionNamesForUserAsync(command.TenantId, user.Id, ct);

        var tokenPair = tokenService.GenerateTokenPair(user, tenant, roles, permissions);

        var lifetime = tenant.RefreshTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value)
            : DefaultRefreshTokenLifetime;

        var refreshToken = RefreshToken.Create(
            tenantId:   command.TenantId,
            userId:     user.Id,
            tokenHash:  tokenService.HashRefreshToken(tokenPair.RefreshToken),
            jti:        Guid.CreateVersion7().ToString(),
            lifetime:   lifetime,
            deviceInfo: payload.DeviceInfo,
            ipAddress:  payload.IpAddress);

        await refreshTokenRepository.CreateAsync(refreshToken, ct);

        logger.LogInformation("User {UserId} completed MFA login in tenant {TenantId}", user.Id, command.TenantId);

        return new CompleteMfaLoginResult(
            AccessToken:        tokenPair.AccessToken,
            RefreshToken:       tokenPair.RefreshToken,
            AccessTokenExpiry:  tokenPair.AccessTokenExpiry,
            RefreshTokenExpiry: tokenPair.RefreshTokenExpiry,
            UserId:             user.Id,
            TenantId:           command.TenantId);
    }
}

