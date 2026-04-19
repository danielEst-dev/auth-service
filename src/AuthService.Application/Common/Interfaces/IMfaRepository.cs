using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IMfaRepository
{
    Task<MfaSecret?> GetSecretByUserIdAsync(Guid userId, CancellationToken ct = default);
    Task CreateSecretAsync(MfaSecret secret, CancellationToken ct = default);
    Task UpdateSecretAsync(MfaSecret secret, CancellationToken ct = default);
    Task DeleteSecretAsync(Guid userId, CancellationToken ct = default);

    Task<IReadOnlyList<MfaRecoveryCode>> GetRecoveryCodesAsync(Guid userId, CancellationToken ct = default);
    Task CreateRecoveryCodesAsync(IEnumerable<MfaRecoveryCode> codes, CancellationToken ct = default);
    Task MarkRecoveryCodeUsedAsync(Guid codeId, CancellationToken ct = default);
    Task<MfaRecoveryCode?> GetUnusedRecoveryCodeByHashAsync(Guid userId, string codeHash, CancellationToken ct = default);
    Task DeleteRecoveryCodesAsync(Guid userId, CancellationToken ct = default);
}
