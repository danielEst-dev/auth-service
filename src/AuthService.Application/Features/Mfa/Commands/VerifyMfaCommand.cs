namespace AuthService.Application.Features.Mfa.Commands;

public sealed record VerifyMfaCommand(Guid TenantId, Guid UserId, string Code);

public sealed record VerifyMfaResult(bool Success, bool IsConfirmed);
