using AuthService.Application.Common.Interfaces;
using AuthService.Application.Features.Auth.Dtos;
using AuthService.Application.Features.Auth.Validators;
using AuthService.Domain.Entities;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using AuthService.Infrastructure.Messaging;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class AuthServiceImpl(
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IRoleRepository roleRepository,
    ITokenService tokenService,
    IPasswordHasher passwordHasher,
    ICacheService cacheService,
    DomainEventDispatcher eventDispatcher,
    ILogger<AuthServiceImpl> logger)
    : Protos.AuthService.AuthServiceBase
{
    private static readonly RegisterUserValidator RegisterValidator = new();
    private static readonly LoginValidator LoginValidator = new();
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);

    private static TimeSpan GetRefreshTokenLifetime(Tenant tenant) =>
        tenant.RefreshTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value)
            : DefaultRefreshTokenLifetime;

    // ── Register ─────────────────────────────────────────────────────────────

    public override async Task<RegisterResponse> Register(
        RegisterRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        // Validate input
        var dto = new RegisterUserDto(request.Email, request.Username, request.Password,
            string.IsNullOrWhiteSpace(request.FirstName) ? null : request.FirstName,
            string.IsNullOrWhiteSpace(request.LastName) ? null : request.LastName);
        var validation = await RegisterValidator.ValidateAsync(dto, context.CancellationToken);
        if (!validation.IsValid)
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                string.Join("; ", validation.Errors.Select(e => e.ErrorMessage))));

        // Validate uniqueness
        var emailExists = await userRepository.ExistsByEmailAsync(
            tenantId, request.Email.ToUpperInvariant(), context.CancellationToken);

        if (emailExists)
            throw new RpcException(new Status(StatusCode.AlreadyExists,
                "A user with that email already exists in this tenant."));

        var usernameExists = await userRepository.ExistsByUsernameAsync(
            tenantId, request.Username.ToUpperInvariant(), context.CancellationToken);

        if (usernameExists)
            throw new RpcException(new Status(StatusCode.AlreadyExists,
                "A user with that username already exists in this tenant."));

        var passwordHash = passwordHasher.Hash(request.Password);

        var user = User.Create(
            tenantId:     tenantId,
            email:        request.Email,
            username:     request.Username,
            passwordHash: passwordHash,
            firstName:    string.IsNullOrWhiteSpace(request.FirstName) ? null : request.FirstName,
            lastName:     string.IsNullOrWhiteSpace(request.LastName)  ? null : request.LastName);

        await userRepository.CreateAsync(user, context.CancellationToken);
        await eventDispatcher.DispatchAndClearAsync(user, context.CancellationToken);

        logger.LogInformation(
            "User {UserId} registered in tenant {TenantId}", user.Id, tenantId);

        return new RegisterResponse
        {
            UserId   = user.Id.ToString(),
            TenantId = tenantId.ToString(),
            Email    = user.Email,
            Username = user.Username
        };
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    public override async Task<LoginResponse> Login(
        LoginRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        // Validate input
        var dto = new LoginDto(request.Email, request.Password,
            string.IsNullOrWhiteSpace(request.DeviceInfo) ? null : request.DeviceInfo,
            string.IsNullOrWhiteSpace(request.IpAddress) ? null : request.IpAddress);
        var validation = await LoginValidator.ValidateAsync(dto, context.CancellationToken);
        if (!validation.IsValid)
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                string.Join("; ", validation.Errors.Select(e => e.ErrorMessage))));

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        var user = await userRepository.GetByEmailAsync(
            tenantId, request.Email.ToUpperInvariant(), context.CancellationToken);

        // Generic error — do not reveal whether email exists
        if (user is null)
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Invalid email or password."));

        if (user.IsCurrentlyLockedOut)
            throw new RpcException(new Status(StatusCode.PermissionDenied,
                "Account is locked. Please try again later."));

        if (!user.IsActive)
            throw new RpcException(new Status(StatusCode.PermissionDenied,
                "Account is inactive."));

        var passwordValid = user.PasswordHash is not null &&
                            passwordHasher.Verify(request.Password, user.PasswordHash);

        if (!passwordValid)
        {
            var policy = tenant.PasswordPolicy;
            user.RecordFailedLogin(policy.MaxFailedAttempts, policy.LockoutDurationMinutes);
            await userRepository.UpdateAsync(user, context.CancellationToken);
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Invalid email or password."));
        }

        user.RecordSuccessfulLogin();
        await userRepository.UpdateAsync(user, context.CancellationToken);

        var roles       = await roleRepository.GetRoleNamesForUserAsync(tenantId, user.Id, context.CancellationToken);
        var permissions = await roleRepository.GetPermissionNamesForUserAsync(tenantId, user.Id, context.CancellationToken);

        var tokenPair = tokenService.GenerateTokenPair(user, tenant, roles, permissions);

        // Persist hashed refresh token
        var tokenHash = tokenService.HashRefreshToken(tokenPair.RefreshToken);
        var refreshToken = Domain.Entities.RefreshToken.Create(
            tenantId:   tenantId,
            userId:     user.Id,
            tokenHash:  tokenHash,
            jti:        Guid.CreateVersion7().ToString(),
            lifetime:   GetRefreshTokenLifetime(tenant),
            deviceInfo: string.IsNullOrWhiteSpace(request.DeviceInfo) ? null : request.DeviceInfo,
            ipAddress:  string.IsNullOrWhiteSpace(request.IpAddress)  ? null : request.IpAddress);

        await refreshTokenRepository.CreateAsync(refreshToken, context.CancellationToken);

        logger.LogInformation(
            "User {UserId} logged in to tenant {TenantId}", user.Id, tenantId);

        return new LoginResponse
        {
            AccessToken           = tokenPair.AccessToken,
            RefreshToken          = tokenPair.RefreshToken,
            AccessTokenExpiresAt  = tokenPair.AccessTokenExpiry.ToUnixTimeSeconds(),
            RefreshTokenExpiresAt = tokenPair.RefreshTokenExpiry.ToUnixTimeSeconds(),
            UserId                = user.Id.ToString(),
            TenantId              = tenantId.ToString(),
            MfaRequired           = tenant.MfaRequired && !user.MfaEnabled
        };
    }

    // ── RefreshToken ──────────────────────────────────────────────────────────

    public override async Task<RefreshTokenResponse> RefreshToken(
        RefreshTokenRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        var tokenHash = tokenService.HashRefreshToken(request.RefreshToken);
        var stored = await refreshTokenRepository.GetByTokenHashAsync(
            tenantId, tokenHash, context.CancellationToken);

        if (stored is null)
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Refresh token is invalid or expired."));

        // Reuse detection: if the token was already revoked, an attacker may have stolen it.
        // Revoke the entire token family for this user as a safety measure.
        if (!stored.IsActive)
        {
            logger.LogWarning(
                "Refresh token reuse detected for user {UserId} in tenant {TenantId} — revoking all tokens",
                stored.UserId, tenantId);
            await refreshTokenRepository.RevokeAllForUserAsync(tenantId, stored.UserId, context.CancellationToken);
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Refresh token has been revoked. Please log in again."));
        }

        var user = await userRepository.GetByIdAsync(tenantId, stored.UserId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found."));

        if (!user.IsActive)
            throw new RpcException(new Status(StatusCode.PermissionDenied, "Account is inactive."));

        // Rotate — revoke old (with replaced_by_id linkage), issue new
        var roles       = await roleRepository.GetRoleNamesForUserAsync(tenantId, user.Id, context.CancellationToken);
        var permissions = await roleRepository.GetPermissionNamesForUserAsync(tenantId, user.Id, context.CancellationToken);
        var newTokenPair = tokenService.GenerateTokenPair(user, tenant, roles, permissions);

        var newHash = tokenService.HashRefreshToken(newTokenPair.RefreshToken);
        var replacement = stored.Rotate(newHash, Guid.CreateVersion7().ToString(), GetRefreshTokenLifetime(tenant));

        await refreshTokenRepository.UpdateAsync(stored, context.CancellationToken);
        await refreshTokenRepository.CreateAsync(replacement, context.CancellationToken);

        return new RefreshTokenResponse
        {
            AccessToken           = newTokenPair.AccessToken,
            RefreshToken          = newTokenPair.RefreshToken,
            AccessTokenExpiresAt  = newTokenPair.AccessTokenExpiry.ToUnixTimeSeconds(),
            RefreshTokenExpiresAt = newTokenPair.RefreshTokenExpiry.ToUnixTimeSeconds()
        };
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    public override async Task<LogoutResponse> Logout(
        LogoutRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        // Blacklist access token in Redis (TTL = remaining lifetime)
        if (!string.IsNullOrWhiteSpace(request.AccessToken))
        {
            var principal = tokenService.ValidateAccessToken(request.AccessToken);
            if (principal is not null)
            {
                var jti = principal.FindFirst("jti")?.Value;
                var exp = principal.FindFirst("exp")?.Value;
                if (jti is not null && long.TryParse(exp, out var expUnix))
                {
                    var expiry = DateTimeOffset.FromUnixTimeSeconds(expUnix) - DateTimeOffset.UtcNow;
                    if (expiry > TimeSpan.Zero)
                        await cacheService.SetAsync($"blacklist:{jti}", "1", expiry,
                            context.CancellationToken);
                }
            }
        }

        // Revoke refresh token
        if (!string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            var tokenHash = tokenService.HashRefreshToken(request.RefreshToken);
            var stored = await refreshTokenRepository.GetByTokenHashAsync(
                tenantId, tokenHash, context.CancellationToken);

            if (stored is not null && stored.IsActive)
            {
                stored.Revoke();
                await refreshTokenRepository.UpdateAsync(stored, context.CancellationToken);
            }
        }

        return new LogoutResponse { Success = true };
    }

    // ── ValidateToken ─────────────────────────────────────────────────────────

    public override async Task<ValidateTokenResponse> ValidateToken(
        ValidateTokenRequest request,
        ServerCallContext context)
    {
        var requestTenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        var principal = tokenService.ValidateAccessToken(request.AccessToken);

        if (principal is null)
            return new ValidateTokenResponse { IsValid = false };

        // Cross-check: the token's tenant_id must match the request's resolved tenant
        var tokenTenantId = principal.FindFirst("tenant_id")?.Value;
        if (tokenTenantId is null || !Guid.TryParse(tokenTenantId, out var parsedTenantId)
            || parsedTenantId != requestTenantId)
        {
            return new ValidateTokenResponse { IsValid = false };
        }

        var jti = principal.FindFirst("jti")?.Value;
        if (jti is not null)
        {
            var blacklisted = await cacheService.ExistsAsync(
                $"blacklist:{jti}", context.CancellationToken);
            if (blacklisted)
                return new ValidateTokenResponse { IsValid = false };
        }

        var userId   = principal.FindFirst("sub")?.Value ?? string.Empty;
        var tenantId = tokenTenantId;
        var roles    = principal.FindAll("role").Select(c => c.Value).ToList();
        var perms    = principal.FindAll("permission").Select(c => c.Value).ToList();

        var response = new ValidateTokenResponse
        {
            IsValid  = true,
            UserId   = userId,
            TenantId = tenantId
        };
        response.Roles.AddRange(roles);
        response.Permissions.AddRange(perms);

        return response;
    }

    // ── GetUserInfo ───────────────────────────────────────────────────────────

    public override async Task<GetUserInfoResponse> GetUserInfo(
        GetUserInfoRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        var user = await userRepository.GetByIdAsync(tenantId, userId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found."));

        var response = new GetUserInfoResponse
        {
            UserId           = user.Id.ToString(),
            TenantId         = tenantId.ToString(),
            Email            = user.Email,
            Username         = user.Username,
            FirstName        = user.FirstName ?? string.Empty,
            LastName         = user.LastName  ?? string.Empty,
            MfaEnabled       = user.MfaEnabled,
            IsEmailConfirmed = user.IsEmailConfirmed
        };

        var roles = await roleRepository.GetRoleNamesForUserAsync(tenantId, user.Id, context.CancellationToken);
        response.Roles.AddRange(roles);

        return response;
    }

}
