using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class MfaSecret : Entity
{
    public Guid UserId { get; private set; }
    public string SecretEncrypted { get; private set; } = string.Empty;
    public string Method { get; private set; } = "totp";
    public bool IsConfirmed { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    private MfaSecret() { }

    public static MfaSecret Create(Guid userId, string secretEncrypted, string method = "totp")
    {
        return new MfaSecret
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            SecretEncrypted = secretEncrypted,
            Method = method,
            IsConfirmed = false,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    public void Confirm()
    {
        IsConfirmed = true;
    }

    public static MfaSecret Reconstitute(
        Guid id, Guid userId, string secretEncrypted, string method,
        bool isConfirmed, DateTimeOffset createdAt)
    {
        return new MfaSecret
        {
            Id = id,
            UserId = userId,
            SecretEncrypted = secretEncrypted,
            Method = method,
            IsConfirmed = isConfirmed,
            CreatedAt = createdAt
        };
    }
}
