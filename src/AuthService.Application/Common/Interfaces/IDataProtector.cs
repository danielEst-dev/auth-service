namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Symmetric protector for data at rest (MFA secrets, signing-key PEM, etc.). One master
/// key in config; per-purpose subkeys are derived via HKDF so two call sites can't
/// accidentally decrypt each other's payloads even with the same master key leaked.
///
/// Callers pass a stable <paramref name="purpose"/> string that identifies the data kind —
/// e.g. <c>"mfa"</c>, <c>"signing-keys"</c>. The purpose must match between Protect and
/// Unprotect for a given ciphertext.
/// </summary>
public interface IDataProtector
{
    string Protect(string purpose, string plaintext);
    string Unprotect(string purpose, string ciphertext);
}

/// <summary>Canonical purpose strings — avoids stringly-typed mistakes at call sites.</summary>
public static class DataProtectionPurposes
{
    public const string Mfa         = "mfa";
    public const string SigningKeys = "signing-keys";
}
