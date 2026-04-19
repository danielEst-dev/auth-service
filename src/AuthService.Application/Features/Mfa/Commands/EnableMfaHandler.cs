using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Mfa.Commands;

public sealed class EnableMfaHandler(
    IUserRepository userRepository,
    IMfaRepository mfaRepository,
    ITotpService totpService,
    IDataProtector dataProtector,
    IConfiguration configuration,
    ILogger<EnableMfaHandler> logger)
    : ICommandHandler<EnableMfaCommand, EnableMfaResult>
{
    public async Task<EnableMfaResult> HandleAsync(EnableMfaCommand command, CancellationToken ct = default)
    {
        var user = await userRepository.GetByIdAsync(command.TenantId, command.UserId, ct)
            ?? throw new NotFoundException("User not found.");

        var issuer      = configuration["Jwt:Issuer"] ?? "AuthService";
        var plainSecret = totpService.GenerateSecret();
        var qrCodeUri   = totpService.GenerateQrCodeUri(issuer, user.Email, plainSecret);

        // Store encrypted — confirmed on first successful VerifyMfa call
        var encrypted = dataProtector.Protect(DataProtectionPurposes.Mfa, plainSecret);
        var mfaSecret = MfaSecret.Create(command.UserId, encrypted);
        await mfaRepository.CreateSecretAsync(mfaSecret, ct);

        logger.LogInformation("MFA setup initiated for user {UserId} in tenant {TenantId}",
            command.UserId, command.TenantId);

        // Plaintext secret leaves only in this response — to be shown once for QR scanning.
        return new EnableMfaResult(plainSecret, qrCodeUri);
    }
}
