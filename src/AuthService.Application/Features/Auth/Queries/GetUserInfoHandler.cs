using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;

namespace AuthService.Application.Features.Auth.Queries;

public sealed class GetUserInfoHandler(
    IUserRepository userRepository,
    IRoleRepository roleRepository)
    : IQueryHandler<GetUserInfoQuery, GetUserInfoResult>
{
    private const string RequiredPermission = "user:read";

    public async Task<GetUserInfoResult> HandleAsync(GetUserInfoQuery query, CancellationToken ct = default)
    {
        if (query.CallerUserId is null)
            throw new AuthenticationException("Authentication required.");

        var isSelf = query.CallerUserId == query.TargetUserId;
        if (!isSelf && !query.CallerPermissions.Contains(RequiredPermission))
            throw new AuthorizationException($"Permission '{RequiredPermission}' is required to read another user's profile.");

        var user = await userRepository.GetByIdAsync(query.TenantId, query.TargetUserId, ct)
            ?? throw new NotFoundException("User not found.");

        var roles = await roleRepository.GetRoleNamesForUserAsync(query.TenantId, user.Id, ct);

        return new GetUserInfoResult(
            UserId:           user.Id,
            TenantId:         query.TenantId,
            Email:            user.Email,
            Username:         user.Username,
            FirstName:        user.FirstName,
            LastName:         user.LastName,
            MfaEnabled:       user.MfaEnabled,
            IsEmailConfirmed: user.IsEmailConfirmed,
            Roles:            roles);
    }
}
