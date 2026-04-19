namespace AuthService.Application.Common.Exceptions;

/// <summary>
/// Thrown when a use case rejects authentication (wrong password, invalid token, expired
/// MFA challenge). Presentation adapters translate this into a transport-level
/// "unauthenticated" response — the caller sees a generic message so we don't leak which
/// check failed.
/// </summary>
public sealed class AuthenticationException(string message) : Exception(message);

/// <summary>
/// Thrown when a use case can authenticate the caller but refuses the action — account
/// locked, inactive, MFA required but not set up, etc. Presentation maps this to
/// "permission denied".
/// </summary>
public sealed class AuthorizationException(string message) : Exception(message);

/// <summary>
/// Thrown when the referenced entity doesn't exist (tenant, user, token). Maps to NotFound.
/// </summary>
public sealed class NotFoundException(string message) : Exception(message);

/// <summary>
/// Thrown when a caller exceeds an abuse threshold (too many login attempts, too many MFA
/// codes, etc.). Carries the retry-after hint; presentation maps to ResourceExhausted.
/// </summary>
public sealed class RateLimitedException(TimeSpan retryAfter)
    : Exception($"Too many requests. Try again in {(int)retryAfter.TotalSeconds} s.")
{
    public TimeSpan RetryAfter { get; } = retryAfter;
}
