namespace AuthService.Application.Features.OAuth.Queries;

public sealed record GetOidcUserInfoQuery(string? BearerToken);

/// <summary>
/// Free-form claim dictionary — OIDC UserInfo responses are JSON objects whose exact
/// shape depends on the scopes in the access token. The controller serializes as-is.
/// </summary>
public sealed record GetOidcUserInfoResult(IReadOnlyDictionary<string, object> Claims);
