using AuthService.Domain.Entities;

namespace AuthService.Application.Common.Interfaces;

public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid tenantId, Guid userId, CancellationToken ct = default);
    Task<User?> GetByEmailAsync(Guid tenantId, string normalizedEmail, CancellationToken ct = default);
    Task<User?> GetByUsernameAsync(Guid tenantId, string normalizedUsername, CancellationToken ct = default);
    Task<bool> ExistsByEmailAsync(Guid tenantId, string normalizedEmail, CancellationToken ct = default);
    Task<bool> ExistsByUsernameAsync(Guid tenantId, string normalizedUsername, CancellationToken ct = default);
    Task<Guid> CreateAsync(User user, CancellationToken ct = default);
    Task UpdateAsync(User user, CancellationToken ct = default);
}