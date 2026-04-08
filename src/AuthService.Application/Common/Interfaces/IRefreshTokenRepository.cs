using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IRefreshTokenRepository
{
    Task<RefreshToken?> GetByTokenHashAsync(Guid tenantId, string tokenHash, CancellationToken ct = default);
    Task<Guid> CreateAsync(RefreshToken token, CancellationToken ct = default);
    Task UpdateAsync(RefreshToken token, CancellationToken ct = default);
    Task RevokeAllForUserAsync(Guid tenantId, Guid userId, CancellationToken ct = default);
}