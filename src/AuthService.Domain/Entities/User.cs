using AuthService.Domain.Common;
using AuthService.Domain.Events;

namespace AuthService.Domain.Entities;

public sealed class User : Entity
{
    public Guid TenantId { get; private set; }
    public string Email { get; private set; } = string.Empty;
    public string NormalizedEmail { get; private set; } = string.Empty;
    public string Username { get; private set; } = string.Empty;
    public string NormalizedUsername { get; private set; } = string.Empty;
    public string? PasswordHash { get; private set; }
    public string? FirstName { get; private set; }
    public string? LastName { get; private set; }
    public string? PhoneNumber { get; private set; }
    public string? AvatarUrl { get; private set; }
    public bool IsActive { get; private set; } = true;
    public bool IsEmailConfirmed { get; private set; }
    public bool IsPhoneConfirmed { get; private set; }
    public bool IsLockedOut { get; private set; }
    public DateTimeOffset? LockoutEndUtc { get; private set; }
    public int FailedLoginCount { get; private set; }
    public bool MfaEnabled { get; private set; }
    public string? ExternalProvider { get; private set; }
    public string? ExternalProviderId { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset UpdatedAt { get; private set; }
    public DateTimeOffset? LastLoginAt { get; private set; }
    public DateTimeOffset? PasswordChangedAt { get; private set; }

    private User() { }

    public static User Create(
        Guid tenantId,
        string email,
        string username,
        string? passwordHash = null,
        string? firstName = null,
        string? lastName = null)
    {
        var user = new User
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            Username = username,
            NormalizedUsername = username.ToUpperInvariant(),
            PasswordHash = passwordHash,
            FirstName = firstName,
            LastName = lastName,
            IsActive = true,
            IsEmailConfirmed = false,
            IsLockedOut = false,
            FailedLoginCount = 0,
            MfaEnabled = false,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        };

        user.AddDomainEvent(new UserRegisteredEvent(user.Id, user.TenantId, user.Email));
        return user;
    }

    public void SetPasswordHash(string passwordHash)
    {
        PasswordHash = passwordHash;
        PasswordChangedAt = DateTimeOffset.UtcNow;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void ConfirmEmail()
    {
        IsEmailConfirmed = true;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void RecordSuccessfulLogin()
    {
        FailedLoginCount = 0;
        IsLockedOut = false;
        LockoutEndUtc = null;
        LastLoginAt = DateTimeOffset.UtcNow;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public void RecordFailedLogin(int maxAttempts, int lockoutMinutes)
    {
        FailedLoginCount++;
        UpdatedAt = DateTimeOffset.UtcNow;

        if (FailedLoginCount >= maxAttempts)
        {
            IsLockedOut = true;
            LockoutEndUtc = DateTimeOffset.UtcNow.AddMinutes(lockoutMinutes);
        }
    }

    public void Unlock()
    {
        IsLockedOut = false;
        FailedLoginCount = 0;
        LockoutEndUtc = null;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    public bool IsCurrentlyLockedOut =>
        IsLockedOut && (LockoutEndUtc is null || LockoutEndUtc > DateTimeOffset.UtcNow);

    public void Deactivate()
    {
        IsActive = false;
        UpdatedAt = DateTimeOffset.UtcNow;
    }

    // Used by repositories to rehydrate from persistence — does not raise domain events
    public static User Reconstitute(
        Guid id, Guid tenantId, string email, string normalizedEmail,
        string username, string normalizedUsername, string? passwordHash,
        string? firstName, string? lastName, string? phoneNumber, string? avatarUrl,
        bool isActive, bool isEmailConfirmed, bool isPhoneConfirmed,
        bool isLockedOut, DateTimeOffset? lockoutEndUtc, int failedLoginCount,
        bool mfaEnabled, string? externalProvider, string? externalProviderId,
        DateTimeOffset createdAt, DateTimeOffset updatedAt,
        DateTimeOffset? lastLoginAt, DateTimeOffset? passwordChangedAt)
    {
        return new User
        {
            Id = id,
            TenantId = tenantId,
            Email = email,
            NormalizedEmail = normalizedEmail,
            Username = username,
            NormalizedUsername = normalizedUsername,
            PasswordHash = passwordHash,
            FirstName = firstName,
            LastName = lastName,
            PhoneNumber = phoneNumber,
            AvatarUrl = avatarUrl,
            IsActive = isActive,
            IsEmailConfirmed = isEmailConfirmed,
            IsPhoneConfirmed = isPhoneConfirmed,
            IsLockedOut = isLockedOut,
            LockoutEndUtc = lockoutEndUtc,
            FailedLoginCount = failedLoginCount,
            MfaEnabled = mfaEnabled,
            ExternalProvider = externalProvider,
            ExternalProviderId = externalProviderId,
            CreatedAt = createdAt,
            UpdatedAt = updatedAt,
            LastLoginAt = lastLoginAt,
            PasswordChangedAt = passwordChangedAt
        };
    }
}