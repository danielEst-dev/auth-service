using System.Security.Cryptography;
using AuthService.Application.Common.Interfaces;
using AuthService.Domain.Entities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Infrastructure.Security;

/// <summary>
/// Orchestrates the signing keypair lifecycle: loads the active key from the DB (or
/// generates one on first run), caches the live <see cref="RsaSecurityKey"/> for
/// the token service, and exposes the JWKS JSON for discovery.
///
/// Responsibility is strictly orchestration — encryption lives in <see cref="IKeyProtector"/>
/// and JWKS serialization lives in <see cref="IJwksBuilder"/>.
/// </summary>
public sealed class SigningKeyService(
    IServiceScopeFactory scopeFactory,
    IDataProtector protector,
    IJwksBuilder jwksBuilder,
    ILogger<SigningKeyService> logger)
    : ISigningKeyService, IHostedService
{
    private RsaSecurityKey? _signingKey;
    private string?         _kid;
    private string?         _jwksJson;

    // ── ISigningKeyService ────────────────────────────────────────────────────

    public string GetKeyId() =>
        _kid ?? throw new InvalidOperationException("SigningKeyService has not been initialized.");

    public string GetJwksJson() =>
        _jwksJson ?? throw new InvalidOperationException("SigningKeyService has not been initialized.");

    // ── Infrastructure-only accessor (used by JwtTokenService) ────────────────

    public RsaSecurityKey GetSigningKey() =>
        _signingKey ?? throw new InvalidOperationException("SigningKeyService has not been initialized.");

    // ── IHostedService ────────────────────────────────────────────────────────

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var repo = scope.ServiceProvider.GetRequiredService<ISigningKeyRepository>();

        var existing = await repo.GetActiveAsync(cancellationToken);
        var (rsa, activeKey) = existing is not null
            ? (LoadPrivateKey(existing.PrivateKeyEncrypted), existing)
            : await GenerateAndStoreAsync(repo, cancellationToken);

        _signingKey = new RsaSecurityKey(rsa) { KeyId = activeKey.Kid };
        _kid        = activeKey.Kid;

        var allKeys = await repo.GetAllPublicAsync(cancellationToken);
        _jwksJson   = jwksBuilder.Build(allKeys);

        logger.LogInformation("Signing key service initialized with kid={Kid}", _kid);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    // ── Private helpers ───────────────────────────────────────────────────────

    private async Task<(RSA, SigningKey)> GenerateAndStoreAsync(
        ISigningKeyRepository repo, CancellationToken ct)
    {
        logger.LogInformation("No active signing key found — generating new RSA-2048 key");
        var rsa = RSA.Create(2048);
        var kid = Guid.CreateVersion7().ToString("N")[..16];
        var now = DateTimeOffset.UtcNow;

        var key = SigningKey.Reconstitute(
            id:                  Guid.CreateVersion7(),
            kid:                 kid,
            algorithm:           "RS256",
            privateKeyEncrypted: protector.Protect(DataProtectionPurposes.SigningKeys, rsa.ExportRSAPrivateKeyPem()),
            publicKeyPem:        rsa.ExportSubjectPublicKeyInfoPem(),
            isActive:            true,
            activatedAt:         now,
            expiresAt:           null,
            createdAt:           now);

        await repo.CreateAsync(key, ct);
        return (rsa, key);
    }

    private RSA LoadPrivateKey(string stored)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(protector.Unprotect(DataProtectionPurposes.SigningKeys, stored));
        return rsa;
    }
}
