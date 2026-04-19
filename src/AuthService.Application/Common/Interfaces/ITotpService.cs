namespace AuthService.Application.Common.Interfaces;

public interface ITotpService
{
    /// <summary>Generates a new random Base32-encoded TOTP secret.</summary>
    string GenerateSecret();

    /// <summary>
    /// Builds an otpauth://totp/... URI suitable for QR code generation.
    /// </summary>
    string GenerateQrCodeUri(string issuer, string email, string base32Secret);

    /// <summary>
    /// Verifies a 6-digit TOTP code against the given Base32 secret.
    /// Accepts codes from the current and adjacent time windows (±30 s).
    /// </summary>
    bool VerifyCode(string base32Secret, string code);
}
