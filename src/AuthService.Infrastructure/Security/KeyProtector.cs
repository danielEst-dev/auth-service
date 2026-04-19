using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthService.Infrastructure.Security;

/// <summary>
/// Encrypts and decrypts signing-key PEM material under a config-provided AES-256 key
/// (<c>SigningKeys:EncryptionKey</c>, 64 hex chars). Prepends a fresh IV to the ciphertext.
///
/// When the config key is unset, the protector transparently passes plaintext through and
/// logs a warning once — dev convenience only. Production MUST supply the key.
/// </summary>
public interface IKeyProtector
{
    string Protect(string plaintext);
    string Unprotect(string ciphertext);
}

public sealed class KeyProtector : IKeyProtector
{
    private readonly byte[]? _key;
    private readonly bool _plaintextFallback;

    public KeyProtector(IConfiguration configuration, ILogger<KeyProtector> logger)
    {
        var hex = configuration["SigningKeys:EncryptionKey"];
        if (string.IsNullOrWhiteSpace(hex))
        {
            logger.LogWarning("SigningKeys:EncryptionKey is not configured — signing key private material will be stored as plaintext (dev only).");
            _plaintextFallback = true;
            return;
        }

        var key = Convert.FromHexString(hex);
        if (key.Length != 32)
            throw new InvalidOperationException("SigningKeys:EncryptionKey must be a 32-byte (64 hex char) value.");

        _key = key;
    }

    public string Protect(string plaintext)
    {
        if (_plaintextFallback) return plaintext;

        using var aes = Aes.Create();
        aes.Key = _key!;
        aes.GenerateIV();
        var cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(plaintext), aes.IV);

        var combined = new byte[aes.IV.Length + cipher.Length];
        aes.IV.CopyTo(combined, 0);
        cipher.CopyTo(combined, aes.IV.Length);
        return Convert.ToBase64String(combined);
    }

    public string Unprotect(string ciphertext)
    {
        if (_plaintextFallback) return ciphertext;

        var combined = Convert.FromBase64String(ciphertext);
        using var aes = Aes.Create();
        aes.Key = _key!;
        var iv     = combined[..16];
        var cipher = combined[16..];
        return Encoding.UTF8.GetString(aes.DecryptCbc(cipher, iv));
    }
}
