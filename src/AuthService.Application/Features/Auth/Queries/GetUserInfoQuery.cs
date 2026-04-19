namespace AuthService.Application.Features.Auth.Queries;

/// <summary>
/// Read a user's profile. Enforces a self-OR-permission check: users may always read
/// their own profile; reading another user's profile requires <c>user:read</c>. The
/// adapter supplies <paramref name="CallerUserId"/> and <paramref name="CallerPermissions"/>
/// from the JWT claims so the handler stays transport-agnostic.
/// </summary>
public sealed record GetUserInfoQuery(
    Guid                  TenantId,
    Guid                  TargetUserId,
    Guid?                 CallerUserId,
    IReadOnlyList<string> CallerPermissions);

public sealed record GetUserInfoResult(
    Guid                  UserId,
    Guid                  TenantId,
    string                Email,
    string                Username,
    string?               FirstName,
    string?               LastName,
    bool                  MfaEnabled,
    bool                  IsEmailConfirmed,
    IReadOnlyList<string> Roles);
