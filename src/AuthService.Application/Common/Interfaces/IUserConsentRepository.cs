using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IUserConsentRepository
{
    Task<UserConsent?> GetAsync(Guid tenantId, Guid userId, Guid clientDbId, CancellationToken ct = default);

    Task CreateAsync(UserConsent consent, CancellationToken ct = default);

    Task UpdateAsync(UserConsent consent, CancellationToken ct = default);
}
