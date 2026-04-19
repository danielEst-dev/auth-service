namespace AuthService.Application.Features.Tenants.Queries;

/// <summary>Look up a tenant by id OR slug. Exactly one must be supplied.</summary>
public sealed record GetTenantQuery(Guid? TenantId, string? Slug);

public sealed record GetTenantResult(
    Guid   TenantId,
    string Slug,
    string Name,
    string Plan,
    string? CustomDomain,
    bool   IsActive,
    bool   MfaRequired,
    int    SessionLifetimeMinutes,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt);
