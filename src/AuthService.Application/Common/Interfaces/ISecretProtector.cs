namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Symmetric encryption for secrets stored at rest (e.g. TOTP shared secrets).
/// Implementations must produce ciphertext that's safe to round-trip through UTF-8 text
/// storage (typically base64).
/// </summary>
public interface ISecretProtector
{
    string Protect(string plaintext);
    string Unprotect(string ciphertext);
}
