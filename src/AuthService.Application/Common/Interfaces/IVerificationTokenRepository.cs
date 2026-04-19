using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IVerificationTokenRepository
{
    Task<VerificationToken?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default);
    Task CreateAsync(VerificationToken token, CancellationToken ct = default);
    Task MarkUsedAsync(Guid tokenId, CancellationToken ct = default);
}
