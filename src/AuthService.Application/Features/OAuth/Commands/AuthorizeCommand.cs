namespace AuthService.Application.Features.OAuth.Commands;

/// <summary>
/// Input to the <c>/oauth/authorize</c> endpoint. <see cref="CallerAccessToken"/> carries
/// the user's gRPC-issued JWT (the auth service currently requires the user to be
/// pre-authenticated via a Bearer header; Phase O3 will replace this with a redirect).
/// </summary>
public sealed record AuthorizeCommand(
    string? ClientId,
    string? RedirectUri,
    string? ResponseType,
    string? Scope,
    string? State,
    string? CodeChallenge,
    string? CodeChallengeMethod,
    string? Nonce,
    string? CallerAccessToken);

/// <summary>The one and only success outcome: redirect the user-agent here.</summary>
public sealed record AuthorizeResult(string CallbackUri);
