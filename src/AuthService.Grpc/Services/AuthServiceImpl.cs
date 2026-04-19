using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Auth.Commands;
using AuthService.Application.Features.Auth.Queries;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class AuthServiceImpl(
    ICommandHandler<RegisterUserCommand,     RegisterUserResult>     registerUser,
    ICommandHandler<LoginCommand,            LoginResult>            login,
    ICommandHandler<CompleteMfaLoginCommand, CompleteMfaLoginResult> completeMfa,
    ICommandHandler<RefreshTokenCommand,     RefreshTokenResult>     refreshToken,
    ICommandHandler<LogoutCommand,           LogoutResult>           logout,
    IQueryHandler<ValidateTokenQuery,        ValidateTokenResult>    validateToken,
    IQueryHandler<GetUserInfoQuery,          GetUserInfoResult>      getUserInfo)
    : Protos.AuthService.AuthServiceBase
{
    public override async Task<RegisterResponse> Register(RegisterRequest request, ServerCallContext context)
    {
        var result = await registerUser.HandleAsync(
            new RegisterUserCommand(
                TenantId:  GrpcTenantHelper.GetRequiredTenantId(context),
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

    public override async Task<LoginResponse> Login(LoginRequest request, ServerCallContext context)
    {
        var result = await login.HandleAsync(
            new LoginCommand(
                TenantId:   GrpcTenantHelper.GetRequiredTenantId(context),
                Email:      request.Email,
                Password:   request.Password,
                DeviceInfo: NullIfBlank(request.DeviceInfo),
                IpAddress:  NullIfBlank(request.IpAddress)),
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

    public override async Task<CompleteMfaLoginResponse> CompleteMfaLogin(
        CompleteMfaLoginRequest request, ServerCallContext context)
    {
        var result = await completeMfa.HandleAsync(
            new CompleteMfaLoginCommand(
                TenantId:        GrpcTenantHelper.GetRequiredTenantId(context),
                MfaPendingToken: request.MfaPendingToken,
                Code:            request.Code),
            context.CancellationToken);

        return new CompleteMfaLoginResponse
        {
            AccessToken           = result.AccessToken,
            RefreshToken          = result.RefreshToken,
            AccessTokenExpiresAt  = result.AccessTokenExpiry.ToUnixTimeSeconds(),
            RefreshTokenExpiresAt = result.RefreshTokenExpiry.ToUnixTimeSeconds(),
            UserId                = result.UserId.ToString(),
            TenantId              = result.TenantId.ToString(),
        };
    }

    public override async Task<RefreshTokenResponse> RefreshToken(
        RefreshTokenRequest request, ServerCallContext context)
    {
        var result = await refreshToken.HandleAsync(
            new RefreshTokenCommand(
                TenantId:     GrpcTenantHelper.GetRequiredTenantId(context),
                RefreshToken: request.RefreshToken,
                PeerIp:       PeerIp(context)),
            context.CancellationToken);

        return new RefreshTokenResponse
        {
            AccessToken           = result.AccessToken,
            RefreshToken          = result.RefreshToken,
            AccessTokenExpiresAt  = result.AccessTokenExpiry.ToUnixTimeSeconds(),
            RefreshTokenExpiresAt = result.RefreshTokenExpiry.ToUnixTimeSeconds(),
        };
    }

    public override async Task<LogoutResponse> Logout(LogoutRequest request, ServerCallContext context)
    {
        var result = await logout.HandleAsync(
            new LogoutCommand(
                TenantId:     GrpcTenantHelper.GetRequiredTenantId(context),
                AccessToken:  NullIfBlank(request.AccessToken),
                RefreshToken: NullIfBlank(request.RefreshToken)),
            context.CancellationToken);

        return new LogoutResponse { Success = result.Success };
    }

    public override async Task<ValidateTokenResponse> ValidateToken(
        ValidateTokenRequest request, ServerCallContext context)
    {
        var result = await validateToken.HandleAsync(
            new ValidateTokenQuery(
                RequestTenantId: GrpcTenantHelper.GetRequiredTenantId(context),
                AccessToken:     request.AccessToken),
            context.CancellationToken);

        var response = new ValidateTokenResponse
        {
            IsValid  = result.IsValid,
            UserId   = result.UserId,
            TenantId = result.TenantId,
        };
        response.Roles.AddRange(result.Roles);
        response.Permissions.AddRange(result.Permissions);
        return response;
    }

    public override async Task<GetUserInfoResponse> GetUserInfo(
        GetUserInfoRequest request, ServerCallContext context)
    {
        if (!Guid.TryParse(request.UserId, out var userId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid user ID."));

        var http = context.GetHttpContext();
        var callerSub = http.User.FindFirst("sub")?.Value;
        Guid? callerId = Guid.TryParse(callerSub, out var parsed) ? parsed : null;
        var callerPerms = http.User.FindAll("permission").Select(c => c.Value).ToList();

        var result = await getUserInfo.HandleAsync(
            new GetUserInfoQuery(
                TenantId:          GrpcTenantHelper.GetRequiredTenantId(context),
                TargetUserId:      userId,
                CallerUserId:      callerId,
                CallerPermissions: callerPerms),
            context.CancellationToken);

        var response = new GetUserInfoResponse
        {
            UserId           = result.UserId.ToString(),
            TenantId         = result.TenantId.ToString(),
            Email            = result.Email,
            Username         = result.Username,
            FirstName        = result.FirstName ?? string.Empty,
            LastName         = result.LastName  ?? string.Empty,
            MfaEnabled       = result.MfaEnabled,
            IsEmailConfirmed = result.IsEmailConfirmed,
        };
        response.Roles.AddRange(result.Roles);
        return response;
    }

    private static string? NullIfBlank(string s) => string.IsNullOrWhiteSpace(s) ? null : s;

    private static string PeerIp(ServerCallContext context)
    {
        var peer = context.Peer ?? "unknown";
        var colon = peer.LastIndexOf(':');
        return colon > 0 ? peer[..colon] : peer;
    }
}
