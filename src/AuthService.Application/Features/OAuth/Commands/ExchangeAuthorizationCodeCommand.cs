namespace AuthService.Application.Features.OAuth.Commands;

/// <summary>Input to <c>/oauth/token</c> with <c>grant_type=authorization_code</c>.</summary>
public sealed record ExchangeAuthorizationCodeCommand(
    string? ClientId,
    string? ClientSecret,
    string? Code,
    string? RedirectUri,
    string? CodeVerifier);
