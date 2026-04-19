using System.Security.Cryptography;
using System.Text;
using AuthService.Application.Common.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthService.Infrastructure.Security;

/// <summary>
/// Single AES-256-CBC protector for all data-at-rest encryption. One master key
/// (<c>DataProtection:EncryptionKey</c>, 64 hex chars / 32 bytes); per-purpose subkeys are
/// HKDF-SHA256 derived so a purpose mismatch during unprotect fails loudly instead of
/// silently decrypting unrelated data.
///
/// Replaces the prior duplicated <c>AesSecretProtector</c> (Mfa:EncryptionKey) and
/// <c>KeyProtector</c> (SigningKeys:EncryptionKey) — one class, one config key, two call
/// sites differentiated by purpose.
///
/// When the config key is absent the protector falls back to identity (plaintext) and
/// logs a warning — dev convenience. Production MUST configure the key.
/// </summary>
public sealed class AesDataProtector : IDataProtector
{
    private readonly byte[]? _masterKey;
    private readonly bool _plaintextFallback;

    public AesDataProtector(IConfiguration configuration, ILogger<AesDataProtector> logger)
    {
        var hex = configuration["DataProtection:EncryptionKey"];
        if (string.IsNullOrWhiteSpace(hex))
        {
            logger.LogWarning("DataProtection:EncryptionKey is not configured — protected data will be stored as plaintext (dev only).");
            _plaintextFallback = true;
            return;
        }

        var key = Convert.FromHexString(hex);
        if (key.Length != 32)
            throw new InvalidOperationException("DataProtection:EncryptionKey must be a 32-byte (64 hex char) value.");

        _masterKey = key;
    }

    public string Protect(string purpose, string plaintext)
    {
        if (_plaintextFallback) return plaintext;

        var subKey = DeriveSubKey(purpose);

        using var aes = Aes.Create();
        aes.Key = subKey;
        aes.GenerateIV();
        var cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(plaintext), aes.IV);

        var combined = new byte[aes.IV.Length + cipher.Length];
        aes.IV.CopyTo(combined, 0);
        cipher.CopyTo(combined, aes.IV.Length);
        return Convert.ToBase64String(combined);
    }

    public string Unprotect(string purpose, string ciphertext)
    {
        if (_plaintextFallback) return ciphertext;

        var combined = Convert.FromBase64String(ciphertext);
        if (combined.Length < 16)
            throw new CryptographicException("Protected payload is too short to contain an IV.");

        var subKey = DeriveSubKey(purpose);

        using var aes = Aes.Create();
        aes.Key = subKey;
        var iv     = combined[..16];
        var cipher = combined[16..];
        return Encoding.UTF8.GetString(aes.DecryptCbc(cipher, iv));
    }

    /// <summary>
    /// HKDF-SHA256 per-purpose key derivation. <c>info</c> is the purpose string; the
    /// master key is the IKM. No salt — we want deterministic subkeys so the same
    /// purpose always yields the same subkey for round-tripping stored ciphertext.
    /// </summary>
    private byte[] DeriveSubKey(string purpose)
    {
        var info = Encoding.UTF8.GetBytes(purpose);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, _masterKey!, 32, salt: null, info: info);
    }
}
