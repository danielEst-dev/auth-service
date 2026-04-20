namespace AuthService.Application.Features.OAuth.Commands;

/// <summary>
/// Shared success shape for every <c>/oauth/token</c> grant. Refresh responses set
/// <see cref="IdToken"/> to null (per OIDC spec — refresh MAY include id_token but
/// typically does not; we keep it simple). Client-credentials responses set
/// <see cref="RefreshToken"/> to null (spec forbids it).
/// </summary>
public sealed record TokenExchangeResult(
    string  AccessToken,
    string  TokenType,
    int     ExpiresIn,
    string? IdToken,
    string? RefreshToken,
    string  Scope);
