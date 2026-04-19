using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IAuthorizationCodeRepository
{
    Task<AuthorizationCode?> GetByCodeHashAsync(Guid tenantId, string codeHash, CancellationToken ct = default);

    Task CreateAsync(AuthorizationCode code, CancellationToken ct = default);

    /// <summary>
    /// Atomically marks the code as redeemed.
    /// Returns false if the code was already redeemed or expired (replay protection).
    /// </summary>
    Task<bool> MarkRedeemedAsync(Guid tenantId, Guid id, CancellationToken ct = default);
}
