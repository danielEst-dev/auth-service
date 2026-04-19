namespace AuthService.Application.Features.Verification.Commands;

public sealed record RequestPasswordResetCommand(Guid TenantId, string? Email);

public sealed record RequestPasswordResetResult(bool Success);
