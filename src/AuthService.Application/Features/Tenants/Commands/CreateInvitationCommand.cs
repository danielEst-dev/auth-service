namespace AuthService.Application.Features.Tenants.Commands;

public sealed record CreateInvitationCommand(Guid TenantId, string Email, Guid? RoleId);

public sealed record CreateInvitationResult(
    Guid   InvitationId,
    string Token,
    DateTimeOffset ExpiresAt);
