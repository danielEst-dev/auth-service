using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Features.Mfa.Services;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Security;

public sealed class MfaRecoveryCodeGenerator(
    IMfaRepository mfaRepository,
    IPasswordHasher passwordHasher) : IMfaRecoveryCodeGenerator
{
    private const int RecoveryCodeCount  = 8;
    private const int RecoveryCodeLength = 8;
    // No ambiguous 0/O, 1/I so codes are legible when read aloud.
    private const string RecoveryCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    public async Task<IReadOnlyList<string>> RegenerateAsync(Guid userId, CancellationToken ct = default)
    {
        await mfaRepository.DeleteRecoveryCodesAsync(userId, ct);

        var plainCodes = Enumerable.Range(0, RecoveryCodeCount)
            .Select(_ => GenerateSecureRecoveryCode())
            .ToList();

        var entities = plainCodes
            .Select(c => MfaRecoveryCode.Create(userId, passwordHasher.Hash(c)))
            .ToList();

        await mfaRepository.CreateRecoveryCodesAsync(entities, ct);
        return plainCodes;
    }

    private static string GenerateSecureRecoveryCode()
    {
        var buf = new char[RecoveryCodeLength];
        for (var i = 0; i < RecoveryCodeLength; i++)
            buf[i] = RecoveryCodeAlphabet[RandomNumberGenerator.GetInt32(RecoveryCodeAlphabet.Length)];
        return new string(buf);
    }
}
