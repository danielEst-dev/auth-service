using AuthService.Domain.Common;

namespace AuthService.Domain.Entities;

public sealed class AuthorizationCode : Entity
{
    public Guid TenantId { get; private set; }
    public string CodeHash { get; private set; } = string.Empty;
    public Guid ClientDbId { get; private set; }   // FK to oauth_clients.id
    public string ClientId { get; private set; } = string.Empty; // the string client_id
    public Guid UserId { get; private set; }
    public string RedirectUri { get; private set; } = string.Empty;
    public IReadOnlyList<string> Scopes { get; private set; } = [];
    public string? CodeChallenge { get; private set; }
    public string CodeChallengeMethod { get; private set; } = "S256";
    public string? Nonce { get; private set; }
    public DateTimeOffset IssuedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public bool IsRedeemed { get; private set; }

    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
    public bool IsValid => !IsRedeemed && !IsExpired;

    private AuthorizationCode() { }

    public static AuthorizationCode Create(
        Guid tenantId,
        Guid clientDbId,
        string clientId,
        Guid userId,
        string codeHash,
        string redirectUri,
        IEnumerable<string> scopes,
        string? codeChallenge,
        string? nonce,
        string codeChallengeMethod = "S256",
        int lifetimeSeconds = 300)
    {
        var now = DateTimeOffset.UtcNow;
        return new AuthorizationCode
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            ClientDbId = clientDbId,
            ClientId = clientId,
            UserId = userId,
            CodeHash = codeHash,
            RedirectUri = redirectUri,
            Scopes = scopes.ToList().AsReadOnly(),
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            Nonce = nonce,
            IssuedAt = now,
            ExpiresAt = now.AddSeconds(lifetimeSeconds),
            IsRedeemed = false
        };
    }

    public static AuthorizationCode Reconstitute(
        Guid id, Guid tenantId, string codeHash,
        Guid clientDbId, string clientId, Guid userId,
        string redirectUri, IReadOnlyList<string> scopes,
        string? codeChallenge, string codeChallengeMethod,
        string? nonce,
        DateTimeOffset issuedAt, DateTimeOffset expiresAt, bool isRedeemed)
    {
        return new AuthorizationCode
        {
            Id = id,
            TenantId = tenantId,
            CodeHash = codeHash,
            ClientDbId = clientDbId,
            ClientId = clientId,
            UserId = userId,
            RedirectUri = redirectUri,
            Scopes = scopes,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            Nonce = nonce,
            IssuedAt = issuedAt,
            ExpiresAt = expiresAt,
            IsRedeemed = isRedeemed
        };
    }
}
