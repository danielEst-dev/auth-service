namespace AuthService.Application.Features.Mfa.Services;

/// <summary>
/// Generates and stores fresh MFA recovery codes for a user, replacing any existing set.
/// Returns the plain-text codes — caller must surface them to the user exactly once.
/// </summary>
public interface IMfaRecoveryCodeGenerator
{
    Task<IReadOnlyList<string>> RegenerateAsync(Guid userId, CancellationToken ct = default);
}
