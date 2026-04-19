using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Auth.Commands;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class AuthServiceImpl(
    IUserRepository userRepository,
    ITenantRepository tenantRepository,
    IRefreshTokenRepository refreshTokenRepository,
    IRoleRepository roleRepository,
    ITokenService tokenService,
    ICacheService cacheService,
    IRateLimiter rateLimiter,
    ICommandHandler<RegisterUserCommand, RegisterUserResult> registerUserHandler,
    ICommandHandler<LoginCommand, LoginResult> loginHandler,
    ICommandHandler<CompleteMfaLoginCommand, CompleteMfaLoginResult> completeMfaLoginHandler,
    ILogger<AuthServiceImpl> logger)
    : Protos.AuthService.AuthServiceBase
{
    private static readonly TimeSpan DefaultRefreshTokenLifetime = TimeSpan.FromDays(7);
    private const int  RefreshLimit = 60;
    private static readonly TimeSpan RefreshWindow = TimeSpan.FromMinutes(1);

    // ── Register ─────────────────────────────────────────────────────────────

    public override async Task<RegisterResponse> Register(
        RegisterRequest request, ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);
        var result = await registerUserHandler.HandleAsync(
            new RegisterUserCommand(
                TenantId:  tenantId,
                Email:     request.Email,
                Username:  request.Username,
                Password:  request.Password,
                FirstName: request.FirstName,
                LastName:  request.LastName),
            context.CancellationToken);

        return new RegisterResponse
        {
            UserId   = result.UserId.ToString(),
            TenantId = result.TenantId.ToString(),
            Email    = result.Email,
            Username = result.Username,
        };
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    public override async Task<LoginResponse> Login(LoginRequest request, ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);
        var result = await loginHandler.HandleAsync(
            new LoginCommand(
                TenantId:   tenantId,
                Email:      request.Email,
                Password:   request.Password,
                DeviceInfo: string.IsNullOrWhiteSpace(request.DeviceInfo) ? null : request.DeviceInfo,
                IpAddress:  string.IsNullOrWhiteSpace(request.IpAddress)  ? null : request.IpAddress),
            context.CancellationToken);

        if (result.Mfa is { } mfa)
        {
            return new LoginResponse
            {
                UserId          = mfa.UserId.ToString(),
                TenantId        = mfa.TenantId.ToString(),
                MfaRequired     = true,
                MfaPendingToken = mfa.MfaPendingToken,
            };
        }

        var t = result.Tokens!;
        return new LoginResponse
        {
            AccessToken           = t.AccessToken,
            RefreshToken          = t.RefreshToken,
            AccessTokenExpiresAt  = t.AccessTokenExpiry.ToUnixTimeSeconds(),
            RefreshTokenExpiresAt = t.RefreshTokenExpiry.ToUnixTimeSeconds(),
            UserId                = t.UserId.ToString(),
            TenantId              = t.TenantId.ToString(),
            MfaRequired           = t.MfaSetupRequired,
        };
    }

    // ── CompleteMfaLogin ──────────────────────────────────────────────────────

    public override async Task<CompleteMfaLoginResponse> CompleteMfaLogin(
        CompleteMfaLoginRequest request, ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);
        var result = await completeMfaLoginHandler.HandleAsync(
            new CompleteMfaLoginCommand(
                TenantId:        tenantId,
                MfaPendingToken: request.MfaPendingToken,
                Code:            request.Code),
            context.CancellationToken);

        return new CompleteMfaLoginResponse
        {
            AccessToken            = result.AccessToken,
            RefreshToken           = result.RefreshToken,
            AccessTokenExpiresAt   = result.AccessTokenExpiry.ToUnixTimeSeconds(),
            RefreshTokenExpiresAt  = result.RefreshTokenExpiry.ToUnixTimeSeconds(),
            UserId                 = result.UserId.ToString(),
            TenantId               = result.TenantId.ToString(),
        };
    }

    // ── RefreshToken ──────────────────────────────────────────────────────────

    public override async Task<RefreshTokenResponse> RefreshToken(
        RefreshTokenRequest request, ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        await EnforceLimitAsync($"rl:refresh:{tenantId}:{PeerIp(context)}",
            RefreshLimit, RefreshWindow, context.CancellationToken);

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        var tokenHash = tokenService.HashRefreshToken(request.RefreshToken);
        var stored = await refreshTokenRepository.GetByTokenHashAsync(
            tenantId, tokenHash, context.CancellationToken);

        if (stored is null)
            throw new RpcException(new Status(StatusCode.Unauthenticated,
                "Refresh token is invalid or expired."));

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

    public override async Task<LogoutResponse> Logout(LogoutRequest request, ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

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
                        await cacheService.SetAsync($"blacklist:{jti}", "1", expiry, context.CancellationToken);
                }
            }
        }

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
        ValidateTokenRequest request, ServerCallContext context)
    {
        var requestTenantId = GrpcTenantHelper.GetRequiredTenantId(context);
        var principal = tokenService.ValidateAccessToken(request.AccessToken);
        if (principal is null)
            return new ValidateTokenResponse { IsValid = false };

        var tokenTenantId = principal.FindFirst("tenant_id")?.Value;
        if (tokenTenantId is null || !Guid.TryParse(tokenTenantId, out var parsedTenantId)
            || parsedTenantId != requestTenantId)
        {
            return new ValidateTokenResponse { IsValid = false };
        }

        var jti = principal.FindFirst("jti")?.Value;
        if (jti is not null)
        {
            var blacklisted = await cacheService.ExistsAsync($"blacklist:{jti}", context.CancellationToken);
            if (blacklisted) return new ValidateTokenResponse { IsValid = false };
        }

        var response = new ValidateTokenResponse
        {
            IsValid  = true,
            UserId   = principal.FindFirst("sub")?.Value ?? string.Empty,
            TenantId = tokenTenantId,
        };
        response.Roles.AddRange(principal.FindAll("role").Select(c => c.Value));
        response.Permissions.AddRange(principal.FindAll("permission").Select(c => c.Value));
        return response;
    }

    // ── GetUserInfo ───────────────────────────────────────────────────────────

    public override async Task<GetUserInfoResponse> GetUserInfo(
        GetUserInfoRequest request, ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        var httpContext = context.GetHttpContext();
        if (httpContext.User.Identity?.IsAuthenticated != true)
            throw new RpcException(new Status(StatusCode.Unauthenticated, "Authentication required."));

        var callerSub = httpContext.User.FindFirst("sub")?.Value;
        var isSelf    = Guid.TryParse(callerSub, out var callerId) && callerId == userId;

        if (!isSelf)
        {
            var callerPerms = httpContext.User.FindAll("permission").Select(c => c.Value).ToList();
            if (!callerPerms.Contains("user:read"))
                throw new RpcException(new Status(StatusCode.PermissionDenied,
                    "Permission 'user:read' is required to read another user's profile."));
        }

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

    // ── Helpers ───────────────────────────────────────────────────────────────

    private async Task EnforceLimitAsync(string key, int limit, TimeSpan window, CancellationToken ct)
    {
        var rl = await rateLimiter.CheckAsync(key, limit, window, ct);
        if (!rl.Allowed)
        {
            logger.LogWarning("Rate limit exceeded for key {Key} ({Current}/{Limit})", key, rl.Current, rl.Limit);
            throw new RpcException(new Status(StatusCode.ResourceExhausted,
                $"Too many requests. Try again in {(int)rl.RetryAfter.TotalSeconds} s."));
        }
    }

    private static TimeSpan GetRefreshTokenLifetime(Domain.Entities.Tenant tenant) =>
        tenant.RefreshTokenLifetimeSeconds.HasValue
            ? TimeSpan.FromSeconds(tenant.RefreshTokenLifetimeSeconds.Value)
            : DefaultRefreshTokenLifetime;

    private static string PeerIp(ServerCallContext context)
    {
        var peer = context.Peer ?? "unknown";
        var colon = peer.LastIndexOf(':');
        return colon > 0 ? peer[..colon] : peer;
    }
}
