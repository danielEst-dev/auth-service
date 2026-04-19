using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class VerificationToken : Entity
{
    public Guid UserId { get; private set; }
    public string TokenHash { get; private set; } = string.Empty;
    public string Purpose { get; private set; } = string.Empty;
    public DateTimeOffset IssuedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public bool IsUsed { get; private set; }
    public DateTimeOffset? UsedAt { get; private set; }

    public bool IsExpired => ExpiresAt <= DateTimeOffset.UtcNow;
    public bool IsValid => !IsUsed && !IsExpired;

    private VerificationToken() { }

    public static VerificationToken Create(
        Guid userId, string tokenHash, string purpose, TimeSpan lifetime)
    {
        return new VerificationToken
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            TokenHash = tokenHash,
            Purpose = purpose,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime),
            IsUsed = false
        };
    }

    public void MarkUsed()
    {
        IsUsed = true;
        UsedAt = DateTimeOffset.UtcNow;
    }

    public static VerificationToken Reconstitute(
        Guid id, Guid userId, string tokenHash, string purpose,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt,
        bool isUsed, DateTimeOffset? usedAt)
    {
        return new VerificationToken
        {
            Id = id,
            UserId = userId,
            TokenHash = tokenHash,
            Purpose = purpose,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            IsUsed = isUsed,
            UsedAt = usedAt
        };
    }
}
