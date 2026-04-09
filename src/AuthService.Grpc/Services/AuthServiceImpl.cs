using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class AuthServiceImpl(
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IRefreshTokenRepository refreshTokenRepository,
    ITokenService tokenService,
    IPasswordHasher passwordHasher,
    ICacheService cacheService,
    ILogger<AuthServiceImpl> logger)
    : Protos.AuthService.AuthServiceBase
{
    private static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(7);

    // ── Register ─────────────────────────────────────────────────────────────

    public override async Task<RegisterResponse> Register(
        RegisterRequest request,
        ServerCallContext context)
    {
        var tenantId = GetTenantId(context);

        // Validate uniqueness
        var emailExists = await userRepository.ExistsByEmailAsync(
            tenantId, request.Email.ToUpperInvariant(), context.CancellationToken);

        if (emailExists)
            throw new RpcException(new Status(StatusCode.AlreadyExists,
                "A user with that email already exists in this tenant."));

        var passwordHash = passwordHasher.Hash(request.Password);

        var user = User.Create(
            tenantId:     tenantId,
            email:        request.Email,
            username:     request.Username,
            passwordHash: passwordHash,
            firstName:    string.IsNullOrWhiteSpace(request.FirstName) ? null : request.FirstName,
            lastName:     string.IsNullOrWhiteSpace(request.LastName)  ? null : request.LastName);

        await userRepository.CreateAsync(user, context.CancellationToken);

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
        var tenantId = GetTenantId(context);

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
            user.RecordFailedLogin(maxAttempts: 5, lockoutMinutes: 15);
            await userRepository.UpdateAsync(user, context.CancellationToken);
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Invalid email or password."));
        }

        user.RecordSuccessfulLogin();
        await userRepository.UpdateAsync(user, context.CancellationToken);

        // TODO: load actual roles/permissions from DB (Phase 2 RBAC)
        var roles       = Array.Empty<string>();
        var permissions = Array.Empty<string>();

        var tokenPair = tokenService.GenerateTokenPair(user, tenant, roles, permissions);

        // Persist hashed refresh token
        var tokenHash = tokenService.HashRefreshToken(tokenPair.RefreshToken);
        var refreshToken = Domain.Entities.RefreshToken.Create(
            tenantId:   tenantId,
            userId:     user.Id,
            tokenHash:  tokenHash,
            jti:        Guid.CreateVersion7().ToString(),
            lifetime:   RefreshTokenLifetime,
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
        var tenantId = GetTenantId(context);

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        var tokenHash = tokenService.HashRefreshToken(request.RefreshToken);
        var stored = await refreshTokenRepository.GetByTokenHashAsync(
            tenantId, tokenHash, context.CancellationToken);

        if (stored is null || !stored.IsActive)
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Refresh token is invalid or expired."));

        var user = await userRepository.GetByIdAsync(tenantId, stored.UserId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "User not found."));

        if (!user.IsActive)
            throw new RpcException(new Status(StatusCode.PermissionDenied, "Account is inactive."));

        // Rotate — revoke old, issue new
        var roles       = Array.Empty<string>();
        var permissions = Array.Empty<string>();
        var newTokenPair = tokenService.GenerateTokenPair(user, tenant, roles, permissions);

        var newHash = tokenService.HashRefreshToken(newTokenPair.RefreshToken);
        var newRefreshToken = Domain.Entities.RefreshToken.Create(
            tenantId:  tenantId,
            userId:    user.Id,
            tokenHash: newHash,
            jti:       Guid.CreateVersion7().ToString(),
            lifetime:  RefreshTokenLifetime,
            deviceInfo: stored.DeviceInfo,
            ipAddress:  stored.IpAddress);

        stored.Revoke();
        await refreshTokenRepository.UpdateAsync(stored, context.CancellationToken);
        await refreshTokenRepository.CreateAsync(newRefreshToken, context.CancellationToken);

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
        var tenantId = GetTenantId(context);

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
        var principal = tokenService.ValidateAccessToken(request.AccessToken);

        if (principal is null)
            return new ValidateTokenResponse { IsValid = false };

        var jti = principal.FindFirst("jti")?.Value;
        if (jti is not null)
        {
            var blacklisted = await cacheService.ExistsAsync(
                $"blacklist:{jti}", context.CancellationToken);
            if (blacklisted)
                return new ValidateTokenResponse { IsValid = false };
        }

        var userId   = principal.FindFirst("sub")?.Value ?? string.Empty;
        var tenantId = principal.FindFirst("tenant_id")?.Value ?? string.Empty;
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
        var tenantId = GetTenantId(context);

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

        // TODO: load roles from DB (Phase 2 RBAC)

        return response;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Guid GetTenantId(ServerCallContext context)
    {
        if (context.UserState.TryGetValue("TenantId", out var value) && value is Guid tenantId)
            return tenantId;

        throw new RpcException(new Status(StatusCode.Internal,
            "Tenant ID was not set by the interceptor."));
    }
}
