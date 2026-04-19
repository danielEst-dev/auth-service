namespace AuthService.Application.Features.Mfa.Commands;

public sealed record EnableMfaCommand(Guid TenantId, Guid UserId);

public sealed record EnableMfaResult(string Secret, string QrCodeUri);
