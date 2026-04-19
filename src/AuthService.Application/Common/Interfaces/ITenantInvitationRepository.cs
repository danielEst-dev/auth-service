using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface ITenantInvitationRepository
{
    Task<TenantInvitation?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<TenantInvitation?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default);
    Task CreateAsync(TenantInvitation invitation, CancellationToken ct = default);
    Task UpdateAsync(TenantInvitation invitation, CancellationToken ct = default);
    Task<bool> ExistsForEmailAsync(Guid tenantId, string email, CancellationToken ct = default);
}