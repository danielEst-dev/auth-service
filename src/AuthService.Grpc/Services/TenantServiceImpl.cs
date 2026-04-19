using System.Security.Cryptography;
using System.Text;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Features.Tenants.Dtos;
using AuthService.Domain.Entities;
using AuthService.Grpc.Helpers;
using AuthService.Grpc.Protos;
using FluentValidation;
using Grpc.Core;

namespace AuthService.Grpc.Services;

public sealed class TenantServiceImpl(
    ITenantRepository tenantRepository,
    IUserRepository userRepository,
    ITenantInvitationRepository invitationRepository,
    IRoleRepository roleRepository,
    IPasswordHasher passwordHasher,
    IDomainEventDispatcher eventDispatcher,
    IValidator<CreateTenantDto> createTenantValidator,
    ILogger<TenantServiceImpl> logger)
    : TenantService.TenantServiceBase
{

    public override async Task<CreateTenantResponse> CreateTenant(
        CreateTenantRequest request,
        ServerCallContext context)
    {
        // Validate input
        var dto = new CreateTenantDto(request.Slug, request.Name,
            string.IsNullOrWhiteSpace(request.Plan) ? "free" : request.Plan);
        var validation = await createTenantValidator.ValidateAsync(dto, context.CancellationToken);
        if (!validation.IsValid)
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                string.Join("; ", validation.Errors.Select(e => e.ErrorMessage))));

        var slugTaken = await tenantRepository.ExistsBySlugAsync(request.Slug, context.CancellationToken);
        if (slugTaken)
            throw new RpcException(new Status(StatusCode.AlreadyExists,
                $"Tenant with slug '{request.Slug}' already exists."));

        var tenant = Tenant.Create(
            slug: request.Slug,
            name: request.Name,
            plan: string.IsNullOrWhiteSpace(request.Plan) ? "free" : request.Plan);

        await tenantRepository.CreateAsync(tenant, context.CancellationToken);
        await eventDispatcher.DispatchAndClearAsync(tenant, context.CancellationToken);

        logger.LogInformation("Tenant {TenantId} ({Slug}) created", tenant.Id, tenant.Slug);

        return new CreateTenantResponse
        {
            TenantId  = tenant.Id.ToString(),
            Slug      = tenant.Slug,
            Name      = tenant.Name,
            Plan      = tenant.Plan,
            CreatedAt = tenant.CreatedAt.ToUnixTimeSeconds()
        };
    }

    public override async Task<GetTenantResponse> GetTenant(
        GetTenantRequest request,
        ServerCallContext context)
    {
        Tenant? tenant = request.LookupCase switch
        {
            GetTenantRequest.LookupOneofCase.TenantId when Guid.TryParse(request.TenantId, out var id)
                => await tenantRepository.GetByIdAsync(id, context.CancellationToken),

            GetTenantRequest.LookupOneofCase.Slug
                => await tenantRepository.GetBySlugAsync(request.Slug, context.CancellationToken),

            _ => throw new RpcException(new Status(StatusCode.InvalidArgument,
                    "Provide either a valid tenant_id or slug."))
        };

        if (tenant is null)
            throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        return new GetTenantResponse
        {
            TenantId               = tenant.Id.ToString(),
            Slug                   = tenant.Slug,
            Name                   = tenant.Name,
            Plan                   = tenant.Plan,
            CustomDomain           = tenant.CustomDomain ?? string.Empty,
            IsActive               = tenant.IsActive,
            MfaRequired            = tenant.MfaRequired,
            SessionLifetimeMinutes = tenant.SessionLifetimeMinutes,
            CreatedAt              = tenant.CreatedAt.ToUnixTimeSeconds(),
            UpdatedAt              = tenant.UpdatedAt.ToUnixTimeSeconds()
        };
    }

    public override async Task<UpdateTenantResponse> UpdateTenant(
        UpdateTenantRequest request,
        ServerCallContext context)
    {
        if (!Guid.TryParse(request.TenantId, out var tenantId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid tenant ID."));

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        if (!string.IsNullOrWhiteSpace(request.Name))
            tenant.UpdateName(request.Name);

        tenant.SetCustomDomain(string.IsNullOrWhiteSpace(request.CustomDomain)
            ? null : request.CustomDomain);

        tenant.RequireMfa(request.MfaRequired);

        if (request.SessionLifetimeMinutes > 0)
            tenant.UpdateSessionLifetime(request.SessionLifetimeMinutes);

        await tenantRepository.UpdateAsync(tenant, context.CancellationToken);

        return new UpdateTenantResponse
        {
            Success   = true,
            UpdatedAt = tenant.UpdatedAt.ToUnixTimeSeconds()
        };
    }

    public override async Task<DeactivateTenantResponse> DeactivateTenant(
        DeactivateTenantRequest request,
        ServerCallContext context)
    {
        if (!Guid.TryParse(request.TenantId, out var tenantId))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Invalid tenant ID."));

        var tenant = await tenantRepository.GetByIdAsync(tenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        tenant.Deactivate();
        await tenantRepository.UpdateAsync(tenant, context.CancellationToken);

        logger.LogInformation("Tenant {TenantId} deactivated", tenantId);

        return new DeactivateTenantResponse { Success = true };
    }

    // ── CreateInvitation ─────────────────────────────────────────────────────

    public override async Task<CreateInvitationResponse> CreateInvitation(
        CreateInvitationRequest request,
        ServerCallContext context)
    {
        var tenantId = GrpcTenantHelper.GetRequiredTenantId(context);

        if (string.IsNullOrWhiteSpace(request.Email))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Email is required."));

        Guid? roleId = Guid.TryParse(request.RoleId, out var rid) ? rid : null;

        var alreadyInvited = await invitationRepository.ExistsForEmailAsync(
            tenantId, request.Email, context.CancellationToken);
        if (alreadyInvited)
            throw new RpcException(new Status(StatusCode.AlreadyExists,
                "An active invitation already exists for this email."));

        var rawToken  = GenerateInvitationToken();
        var tokenHash = HashToken(rawToken);
        var invitation = TenantInvitation.Create(
            tenantId, request.Email, tokenHash, roleId);

        await invitationRepository.CreateAsync(invitation, context.CancellationToken);

        logger.LogInformation("Invitation {InvitationId} created for {Email} in tenant {TenantId}",
            invitation.Id, request.Email, tenantId);

        // TODO (Phase 5): dispatch InvitationCreatedEvent so email consumer sends the invite link

        return new CreateInvitationResponse
        {
            InvitationId = invitation.Id.ToString(),
            Token       = rawToken,
            ExpiresAt   = invitation.ExpiresAt.ToUnixTimeSeconds()
        };
    }

    // ── AcceptInvitation ─────────────────────────────────────────────────────

    public override async Task<AcceptInvitationResponse> AcceptInvitation(
        AcceptInvitationRequest request,
        ServerCallContext context)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Token is required."));

        if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length < 8)
            throw new RpcException(new Status(StatusCode.InvalidArgument,
                "Password must be at least 8 characters."));

        if (string.IsNullOrWhiteSpace(request.Username))
            throw new RpcException(new Status(StatusCode.InvalidArgument, "Username is required."));

        var tokenHash = HashToken(request.Token);
        var invitation = await invitationRepository.GetByTokenHashAsync(tokenHash, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Invitation not found."));

        if (invitation.IsAccepted)
            throw new RpcException(new Status(StatusCode.FailedPrecondition,
                "Invitation has already been accepted."));

        if (invitation.IsExpired)
            throw new RpcException(new Status(StatusCode.FailedPrecondition,
                "Invitation has expired."));

        var tenant = await tenantRepository.GetByIdAsync(invitation.TenantId, context.CancellationToken)
            ?? throw new RpcException(new Status(StatusCode.NotFound, "Tenant not found."));

        // Create user from invitation (pre-verified, raises TenantInvitationAcceptedEvent)
        var passwordHash = passwordHasher.Hash(request.Password);
        var user = User.CreateFromInvitation(
            invitationId: invitation.Id,
            tenantId:     invitation.TenantId,
            email:        invitation.Email,
            username:     request.Username,
            passwordHash: passwordHash);

        await userRepository.CreateAsync(user, context.CancellationToken);

        // Assign pre-configured role if specified
        if (invitation.RoleId.HasValue)
        {
            await roleRepository.AssignRoleAsync(
                invitation.TenantId, user.Id, invitation.RoleId.Value, null,
                context.CancellationToken);
        }

        // Mark invitation accepted
        invitation.Accept();
        await invitationRepository.UpdateAsync(invitation, context.CancellationToken);

        // Dispatch domain events
        await eventDispatcher.DispatchAndClearAsync(user, context.CancellationToken);

        logger.LogInformation(
            "Invitation {InvitationId} accepted — user {UserId} created in tenant {TenantId}",
            invitation.Id, user.Id, invitation.TenantId);

        return new AcceptInvitationResponse
        {
            UserId   = user.Id.ToString(),
            TenantId = invitation.TenantId.ToString(),
            Email    = invitation.Email
        };
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string GenerateInvitationToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static string HashToken(string rawToken)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
