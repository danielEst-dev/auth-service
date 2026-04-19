namespace AuthService.Application.Features.Verification.Commands;

public sealed record ResetPasswordCommand(Guid TenantId, string Token, string NewPassword, string PeerIp);

public sealed record ResetPasswordResult(bool Success);
