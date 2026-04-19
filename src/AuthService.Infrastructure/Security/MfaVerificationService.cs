using AuthService.Application.Common.Interfaces;

namespace AuthService.Infrastructure.Security;

public sealed class MfaVerificationService(
    IMfaRepository mfaRepository,
    ITotpService totpService,
    IDataProtector dataProtector,
    IPasswordHasher passwordHasher) : IMfaVerificationService
{
    public async Task<bool> VerifyAsync(Guid userId, string code, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(code))
            return false;

        var secret = await mfaRepository.GetSecretByUserIdAsync(userId, ct);
        if (secret is null)
            return false;

        // TOTP first — common path, no DB scan
        var plainSecret = dataProtector.Unprotect(DataProtectionPurposes.Mfa, secret.SecretEncrypted);
        if (totpService.VerifyCode(plainSecret, code))
            return true;

        // Recovery code fallback. Argon2 hashes are salted so we must scan unused codes.
        var unused = await mfaRepository.GetRecoveryCodesAsync(userId, ct);
        foreach (var rc in unused.Where(c => !c.IsUsed))
        {
            if (passwordHasher.Verify(code, rc.CodeHash))
            {
                await mfaRepository.MarkRecoveryCodeUsedAsync(rc.Id, ct);
                return true;
            }
        }

        return false;
    }
}
