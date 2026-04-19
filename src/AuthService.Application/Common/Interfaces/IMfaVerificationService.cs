namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Verifies an MFA code (TOTP or recovery) against a user's stored secret + recovery codes.
/// Marks the matched recovery code as used on success. TOTP is tried first, recovery as fallback.
/// </summary>
public interface IMfaVerificationService
{
    /// <summary>
    /// Returns <c>true</c> if <paramref name="code"/> is a valid TOTP or unused recovery code
    /// for the user. A matched recovery code is atomically marked used.
    /// </summary>
    Task<bool> VerifyAsync(Guid userId, string code, CancellationToken ct = default);
}
