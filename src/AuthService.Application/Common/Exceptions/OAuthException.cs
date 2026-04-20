namespace AuthService.Application.Common.Exceptions;

/// <summary>
/// Spec-shaped OAuth2 / OIDC error. Carries the <c>error</c> and <c>error_description</c>
/// fields that RFC 6749 requires, plus optional redirect metadata for the authorize endpoint:
///
/// * When <see cref="RedirectUri"/> is set, the MVC filter redirects the user-agent to
///   that URI with the error params appended (per RFC 6749 §4.1.2.1). Used for errors
///   AFTER the client + redirect_uri have been validated.
/// * When <see cref="RedirectUri"/> is null, the filter returns a JSON error body with
///   <see cref="StatusCode"/>. Used for errors BEFORE the redirect_uri is trusted
///   (invalid client_id, invalid redirect_uri itself).
///
/// Token/userinfo endpoints always return JSON — they set RedirectUri=null.
/// </summary>
public sealed class OAuthException(
    string error,
    string description,
    string? redirectUri = null,
    string? state = null,
    int statusCode = 400) : Exception(description)
{
    public string  Error            { get; } = error;
    public string  ErrorDescription { get; } = description;
    public string? RedirectUri      { get; } = redirectUri;
    public string? State            { get; } = state;
    public int     StatusCode       { get; } = statusCode;
}
