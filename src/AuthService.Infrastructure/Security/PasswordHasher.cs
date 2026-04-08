using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using Konscious.Security.Cryptography;

namespace AuthService.Infrastructure.Security;

public sealed class PasswordHasher : IPasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 3;
    private const int MemorySize = 65536;   // 64 MB
    private const int DegreeOfParallelism = 1;

    public string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);

        using var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            Iterations = Iterations,
            MemorySize = MemorySize,
            DegreeOfParallelism = DegreeOfParallelism
        };

        var hash = argon2.GetBytes(HashSize);

        // Format: $argon2id$v=19$m=65536,t=3,p=1$<salt-b64>$<hash-b64>
        return $"$argon2id$v=19$m={MemorySize},t={Iterations},p={DegreeOfParallelism}" +
               $"${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public bool Verify(string password, string storedHash)
    {
        try
        {
            var parts = storedHash.Split('$', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 5) return false;

            // parts[0] = "argon2id", parts[1] = "v=19", parts[2] = params, parts[3] = salt, parts[4] = hash
            var salt = Convert.FromBase64String(parts[3]);
            var expectedHash = Convert.FromBase64String(parts[4]);

            using var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                Iterations = Iterations,
                MemorySize = MemorySize,
                DegreeOfParallelism = DegreeOfParallelism
            };

            var actualHash = argon2.GetBytes(HashSize);
            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
        catch
        {
            return false;
        }
    }
}