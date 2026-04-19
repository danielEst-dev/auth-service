namespace AuthService.Application.Features.Mfa.Commands;

public sealed record GenerateRecoveryCodesCommand(Guid TenantId, Guid UserId);

public sealed record GenerateRecoveryCodesResult(IReadOnlyList<string> Codes);
