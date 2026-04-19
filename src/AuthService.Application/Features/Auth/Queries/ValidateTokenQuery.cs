namespace AuthService.Application.Features.Auth.Queries;

public sealed record ValidateTokenQuery(Guid RequestTenantId, string AccessToken);

public sealed record ValidateTokenResult(
    bool                  IsValid,
    string                UserId,
    string                TenantId,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions)
{
    public static ValidateTokenResult Invalid() =>
        new(false, string.Empty, string.Empty, [], []);
}
