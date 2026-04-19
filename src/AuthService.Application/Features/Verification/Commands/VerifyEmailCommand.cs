namespace AuthService.Application.Features.Verification.Commands;

public sealed record VerifyEmailCommand(Guid TenantId, string Token, string PeerIp);

public sealed record VerifyEmailResult(bool Success);
