using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

/// <summary>
/// Repository for RSA signing keys. Global (no tenant context) — signing_keys has no tenant_id.
/// </summary>
public interface ISigningKeyRepository
{
    Task<SigningKey?> GetActiveAsync(CancellationToken ct = default);

    Task<IReadOnlyList<SigningKey>> GetAllPublicAsync(CancellationToken ct = default);

    Task CreateAsync(SigningKey key, CancellationToken ct = default);

    Task DeactivateAllAsync(CancellationToken ct = default);
}
