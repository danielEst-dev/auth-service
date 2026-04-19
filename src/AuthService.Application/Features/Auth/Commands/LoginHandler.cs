using System.Text.Json;
using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Auth.Dtos;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Auth.Commands;

public sealed class LoginHandler(
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IRoleRepository roleRepository,
    ITokenService tokenService,
    IPasswordHasher passwordHasher,
    ICacheService cacheService,
    IRateLimiter rateLimiter,
    IDomainEventDispatcher eventDispatcher,
    IValidator<LoginDto> validator,
    ILogger<LoginHandler> logger)
    : ICommandHandler<LoginCommand, LoginResult>
{
    private const int LoginLimit = 10;
    private static readonly TimeSpan LoginWindow = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);
    private static readonly TimeSpan MfaPendingTtl = TimeSpan.FromMinutes(5);

    public async Task<LoginResult> HandleAsync(LoginCommand command, CancellationToken ct = default)
    {
        // Rate-limit by {tenant}:{ip} — the peer IP is the strongest anti-brute-force signal
        await EnforceLimitAsync($"rl:login:{command.TenantId}:{command.IpAddress ?? "unknown"}", ct);

        var validation = await validator.ValidateAsync(
            new LoginDto(command.Email, command.Password, command.DeviceInfo, command.IpAddress), ct);
        if (!validation.IsValid)
            throw new ValidationException(validation.Errors);

        var tenant = await tenantRepository.GetByIdAsync(command.TenantId, ct)
            ?? throw new NotFoundException("Tenant not found.");

        var user = await userRepository.GetByEmailAsync(command.TenantId, command.Email.ToUpperInvariant(), ct);
        if (user is null)
            throw new AuthenticationException("Invalid email or password.");

        if (user.IsCurrentlyLockedOut)
            throw new AuthorizationException("Account is locked. Please try again later.");

        if (!user.IsActive)
            throw new AuthorizationException("Account is inactive.");

        var passwordValid = user.PasswordHash is not null
            && passwordHasher.Verify(command.Password, user.PasswordHash);

        if (!passwordValid)
        {
            var policy = tenant.PasswordPolicy;
            user.RecordFailedLogin(policy.MaxFailedAttempts, policy.LockoutDurationMinutes);
            await userRepository.UpdateAsync(user, ct);
            await eventDispatcher.DispatchAndClearAsync(user, ct);
            throw new AuthenticationException("Invalid email or password.");
        }

        user.RecordSuccessfulLogin(command.DeviceInfo);
        await userRepository.UpdateAsync(user, ct);
        await eventDispatcher.DispatchAndClearAsync(user, ct);

        // MFA gate: tenant requires MFA AND user has it enabled → issue a pending token,
        // NO access/refresh tokens. Roles/permissions are re-fetched on completion so
        // role changes during the 5-minute window take effect immediately.
        if (tenant.MfaRequired && user.MfaEnabled)
        {
            var pendingToken = Guid.CreateVersion7().ToString("N");
            var payload = JsonSerializer.Serialize(new MfaPendingPayload(
                user.Id, command.TenantId, command.DeviceInfo, command.IpAddress));

            await cacheService.SetAsync($"mfa_pending:{pendingToken}", payload, MfaPendingTtl, ct);

            logger.LogInformation("MFA challenge issued for user {UserId} in tenant {TenantId}", user.Id, command.TenantId);

            return LoginResult.MfaChallenge(new MfaChallengeResult(pendingToken, user.Id, command.TenantId));
        }

        var roles       = await roleRepository.GetRoleNamesForUserAsync(command.TenantId, user.Id, ct);
        var permissions = await roleRepository.GetPermissionNamesForUserAsync(command.TenantId, user.Id, ct);

        var tokenPair = tokenService.GenerateTokenPair(user, tenant, roles, permissions);
        await PersistRefreshTokenAsync(command, user, tenant, tokenPair, ct);

        logger.LogInformation("User {UserId} logged in to tenant {TenantId}", user.Id, command.TenantId);

        return LoginResult.TokensIssued(new TokensIssuedResult(
            AccessToken:        tokenPair.AccessToken,
            RefreshToken:       tokenPair.RefreshToken,
            AccessTokenExpiry:  tokenPair.AccessTokenExpiry,
            RefreshTokenExpiry: tokenPair.RefreshTokenExpiry,
            UserId:             user.Id,
            TenantId:           command.TenantId,
            MfaSetupRequired:   tenant.MfaRequired && !user.MfaEnabled));
    }

    private async Task PersistRefreshTokenAsync(
        LoginCommand command, User user, Tenant tenant, TokenPair pair, CancellationToken ct)
    {
        var lifetime = tenant.RefreshTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value)
            : DefaultRefreshTokenLifetime;

        var refreshToken = RefreshToken.Create(
            tenantId:   command.TenantId,
            userId:     user.Id,
            tokenHash:  tokenService.HashRefreshToken(pair.RefreshToken),
            jti:        Guid.CreateVersion7().ToString(),
            lifetime:   lifetime,
            deviceInfo: command.DeviceInfo,
            ipAddress:  command.IpAddress);

        await refreshTokenRepository.CreateAsync(refreshToken, ct);
    }

    private async Task EnforceLimitAsync(string key, CancellationToken ct)
    {
        var rl = await rateLimiter.CheckAsync(key, LoginLimit, LoginWindow, ct);
        if (!rl.Allowed)
        {
            logger.LogWarning("Login rate limit exceeded for key {Key} ({Current}/{Limit})", key, rl.Current, rl.Limit);
            throw new RateLimitedException(rl.RetryAfter);
        }
    }
}
