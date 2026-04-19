namespace AuthService.Application.Features.Tenants.Commands;

public sealed record AcceptInvitationCommand(string Token, string Password, string Username);

public sealed record AcceptInvitationResult(Guid UserId, Guid TenantId, string Email);
