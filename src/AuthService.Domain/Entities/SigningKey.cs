using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class SigningKey : Entity
{
    public string Kid { get; private set; } = string.Empty;
    public string Algorithm { get; private set; } = "RS256";
    public string PrivateKeyEncrypted { get; private set; } = string.Empty;
    public string PublicKeyPem { get; private set; } = string.Empty;
    public bool IsActive { get; private set; }
    public DateTimeOffset ActivatedAt { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    private SigningKey() { }

    public static SigningKey Reconstitute(
        Guid id, string kid, string algorithm,
        string privateKeyEncrypted, string publicKeyPem,
        bool isActive, DateTimeOffset activatedAt,
        DateTimeOffset? expiresAt, DateTimeOffset createdAt)
    {
        return new SigningKey
        {
            Id = id,
            Kid = kid,
            Algorithm = algorithm,
            PrivateKeyEncrypted = privateKeyEncrypted,
            PublicKeyPem = publicKeyPem,
            IsActive = isActive,
            ActivatedAt = activatedAt,
            ExpiresAt = expiresAt,
            CreatedAt = createdAt
        };
    }
}
