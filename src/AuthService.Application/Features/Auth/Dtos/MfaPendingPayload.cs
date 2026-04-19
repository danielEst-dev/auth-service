namespace AuthService.Application.Features.Auth.Dtos;

/// <summary>
/// Shape persisted to Redis under <c>mfa_pending:{token}</c> during the MFA-gated login flow.
/// Roles/permissions are intentionally NOT cached here — they're re-fetched on completion so
/// role changes during the 5-minute window take effect immediately.
/// </summary>
public sealed record MfaPendingPayload(
    Guid    UserId,
    Guid    TenantId,
    string? DeviceInfo,
    string? IpAddress);
