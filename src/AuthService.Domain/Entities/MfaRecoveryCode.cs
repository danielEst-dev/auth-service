using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class MfaRecoveryCode : Entity
{
    public Guid UserId { get; private set; }
    public string CodeHash { get; private set; } = string.Empty;
    public bool IsUsed { get; private set; }
    public DateTimeOffset? UsedAt { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }

    private MfaRecoveryCode() { }

    public static MfaRecoveryCode Create(Guid userId, string codeHash)
    {
        return new MfaRecoveryCode
        {
            Id = Guid.CreateVersion7(),
            UserId = userId,
            CodeHash = codeHash,
            IsUsed = false,
            CreatedAt = DateTimeOffset.UtcNow
        };
    }

    public void MarkUsed()
    {
        IsUsed = true;
        UsedAt = DateTimeOffset.UtcNow;
    }

    public static MfaRecoveryCode Reconstitute(
        Guid id, Guid userId, string codeHash,
        bool isUsed, DateTimeOffset? usedAt, DateTimeOffset createdAt)
    {
        return new MfaRecoveryCode
        {
            Id = id,
            UserId = userId,
            CodeHash = codeHash,
            IsUsed = isUsed,
            UsedAt = usedAt,
            CreatedAt = createdAt
        };
    }
}
