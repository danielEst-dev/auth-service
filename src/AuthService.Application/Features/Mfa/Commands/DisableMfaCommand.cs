namespace AuthService.Application.Features.Mfa.Commands;

public sealed record DisableMfaCommand(Guid TenantId, Guid UserId, string Code);

public sealed record DisableMfaResult(bool Success);
