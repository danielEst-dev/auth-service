using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class RefreshToken : Entity
{
    public Guid TenantId { get; private set; }
    public Guid UserId { get; private set; }
    public string TokenHash { get; private set; } = string.Empty;
    public string Jti { get; private set; } = string.Empty;
    public string? DeviceInfo { get; private set; }
    public string? IpAddress { get; private set; }
    public DateTimeOffset IssuedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public Guid? ReplacedById { get; private set; }

    public bool IsActive => RevokedAt is null && ExpiresAt > DateTimeOffset.UtcNow;

    private RefreshToken() { }

    public static RefreshToken Create(
        Guid tenantId,
        Guid userId,
        string tokenHash,
        string jti,
        TimeSpan lifetime,
        string? deviceInfo = null,
        string? ipAddress = null)
    {
        return new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            UserId = userId,
            TokenHash = tokenHash,
            Jti = jti,
            DeviceInfo = deviceInfo,
            IpAddress = ipAddress,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.Add(lifetime)
        };
    }

    public RefreshToken Rotate(string newTokenHash, string newJti, TimeSpan? lifetime = null)
    {
        RevokedAt = DateTimeOffset.UtcNow;
        var replacement = Create(TenantId, UserId, newTokenHash, newJti, lifetime ?? (ExpiresAt - IssuedAt), DeviceInfo, IpAddress);
        ReplacedById = replacement.Id;
        return replacement;
    }

    public void Revoke()
    {
        RevokedAt = DateTimeOffset.UtcNow;
    }

    public static RefreshToken Reconstitute(
        Guid id, Guid tenantId, Guid userId,
        string tokenHash, string jti,
        string? deviceInfo, string? ipAddress,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt,
        DateTimeOffset? revokedAt, Guid? replacedById)
    {
        return new RefreshToken
        {
            Id = id,
            TenantId = tenantId,
            UserId = userId,
            TokenHash = tokenHash,
            Jti = jti,
            DeviceInfo = deviceInfo,
            IpAddress = ipAddress,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            RevokedAt = revokedAt,
            ReplacedById = replacedById
        };
    }
}