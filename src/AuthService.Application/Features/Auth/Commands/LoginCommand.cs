namespace AuthService.Application.Features.Auth.Commands;

public sealed record LoginCommand(
    Guid    TenantId,
    string  Email,
    string  Password,
    string? DeviceInfo,
    string? IpAddress);

/// <summary>
/// Result of a login attempt. Exactly one of two modes:
/// <list type="bullet">
///   <item><description><see cref="TokensIssued"/> branch — credentials valid and no MFA gate. Fields: access/refresh tokens, expiries, user/tenant IDs, <c>MfaSetupRequired</c> flag hint for tenants that require MFA but the user hasn't enrolled yet.</description></item>
///   <item><description><see cref="MfaChallenge"/> branch — credentials valid but tenant requires MFA and user has it enabled; caller must next invoke <c>CompleteMfaLogin</c> with the <c>MfaPendingToken</c>.</description></item>
/// </list>
/// </summary>
public sealed record LoginResult
{
    public TokensIssuedResult?  Tokens  { get; init; }
    public MfaChallengeResult?  Mfa     { get; init; }

    public static LoginResult TokensIssued(TokensIssuedResult tokens) => new() { Tokens = tokens };
    public static LoginResult MfaChallenge(MfaChallengeResult mfa)    => new() { Mfa = mfa };
}

public sealed record TokensIssuedResult(
    string         AccessToken,
    string         RefreshToken,
    DateTimeOffset AccessTokenExpiry,
    DateTimeOffset RefreshTokenExpiry,
    Guid           UserId,
    Guid           TenantId,
    bool           MfaSetupRequired);

public sealed record MfaChallengeResult(
    string MfaPendingToken,
    Guid   UserId,
    Guid   TenantId);
