using System.Security.Cryptography;
using System.Text;
using AuthService.Application.Common.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthService.Infrastructure.Security;

/// <summary>
/// AES-256-CBC symmetric protector keyed by <c>Mfa:EncryptionKey</c> (64-hex / 32 bytes).
/// Each call generates a fresh random IV which is prepended to the ciphertext.
///
/// If the config key is absent the protector falls back to identity (plaintext passthrough)
/// and logs a warning once at startup — the same convention as <see cref="SigningKeyService"/>.
/// Dev/test convenience; prod deployments MUST supply the key.
/// </summary>
public sealed class AesSecretProtector : ISecretProtector
{
    private readonly byte[]? _key;
    private readonly bool _plaintextFallback;

    public AesSecretProtector(IConfiguration configuration, ILogger<AesSecretProtector> logger)
    {
        var hex = configuration["Mfa:EncryptionKey"];
        if (string.IsNullOrWhiteSpace(hex))
        {
            logger.LogWarning("Mfa:EncryptionKey is not configured — MFA secrets will be stored as plaintext (dev only).");
            _plaintextFallback = true;
            return;
        }

        var key = Convert.FromHexString(hex);
        if (key.Length != 32)
            throw new InvalidOperationException("Mfa:EncryptionKey must be a 32-byte (64 hex char) value.");

        _key = key;
    }

    public string Protect(string plaintext)
    {
        if (_plaintextFallback) return plaintext;

        using var aes = Aes.Create();
        aes.Key = _key!;
        aes.GenerateIV();

        var plain = Encoding.UTF8.GetBytes(plaintext);
        var cipher = aes.EncryptCbc(plain, aes.IV);

        var combined = new byte[aes.IV.Length + cipher.Length];
        aes.IV.CopyTo(combined, 0);
        cipher.CopyTo(combined, aes.IV.Length);
        return Convert.ToBase64String(combined);
    }

    public string Unprotect(string ciphertext)
    {
        if (_plaintextFallback) return ciphertext;

        var combined = Convert.FromBase64String(ciphertext);
        if (combined.Length < 16)
            throw new CryptographicException("Protected payload is too short to contain an IV.");

        using var aes = Aes.Create();
        aes.Key = _key!;
        var iv = combined[..16];
        var cipher = combined[16..];
        var plain = aes.DecryptCbc(cipher, iv);
        return Encoding.UTF8.GetString(plain);
    }
}
