namespace AuthService.Domain.Entities;

/// <summary>
/// Per-tenant password and lockout policy, stored as JSONB in tenants.password_policy.
/// All properties have safe defaults matching the schema's DEFAULT value.
/// </summary>
public sealed class PasswordPolicy
{
    public int MinLength { get; init; } = 8;
    public bool RequireUppercase { get; init; } = true;
    public bool RequireDigit { get; init; } = true;
    public bool RequireSymbol { get; init; } = false;
    public int MaxFailedAttempts { get; init; } = 5;
    public int LockoutDurationMinutes { get; init; } = 15;

    public static readonly PasswordPolicy Default = new();
}
