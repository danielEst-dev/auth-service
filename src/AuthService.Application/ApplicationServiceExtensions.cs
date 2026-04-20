using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Auth.Commands;
using AuthService.Application.Features.Auth.Dtos;
using AuthService.Application.Features.Auth.Queries;
using AuthService.Application.Features.Auth.Validators;
using AuthService.Application.Features.Mfa.Commands;
using AuthService.Application.Features.OAuth.Commands;
using AuthService.Application.Features.OAuth.Queries;
using AuthService.Application.Features.Roles.Commands;
using AuthService.Application.Features.Roles.Queries;
using AuthService.Application.Features.Tenants.Commands;
using AuthService.Application.Features.Tenants.Queries;
using AuthService.Application.Features.Tenants.Dtos;
using AuthService.Application.Features.Tenants.Validators;
using AuthService.Application.Features.Verification.Commands;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace AuthService.Application;

public static class ApplicationServiceExtensions
{
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        // Validators — injected via IValidator<T> so rules can evolve to depend on services later
        services.AddTransient<IValidator<RegisterUserDto>, RegisterUserValidator>();
        services.AddTransient<IValidator<LoginDto>,        LoginValidator>();
        services.AddTransient<IValidator<CreateTenantDto>, CreateTenantValidator>();

        // Auth handlers
        services.AddScoped<ICommandHandler<RegisterUserCommand,     RegisterUserResult>,     RegisterUserHandler>();
        services.AddScoped<ICommandHandler<LoginCommand,            LoginResult>,            LoginHandler>();
        services.AddScoped<ICommandHandler<CompleteMfaLoginCommand, CompleteMfaLoginResult>, CompleteMfaLoginHandler>();
        services.AddScoped<ICommandHandler<RefreshTokenCommand,     RefreshTokenResult>,     RefreshTokenHandler>();
        services.AddScoped<ICommandHandler<LogoutCommand,           LogoutResult>,           LogoutHandler>();
        services.AddScoped<IQueryHandler<ValidateTokenQuery,        ValidateTokenResult>,    ValidateTokenHandler>();
        services.AddScoped<IQueryHandler<GetUserInfoQuery,          GetUserInfoResult>,      GetUserInfoHandler>();

        // MFA handlers
        services.AddScoped<ICommandHandler<EnableMfaCommand,             EnableMfaResult>,             EnableMfaHandler>();
        services.AddScoped<ICommandHandler<VerifyMfaCommand,             VerifyMfaResult>,             VerifyMfaHandler>();
        services.AddScoped<ICommandHandler<DisableMfaCommand,            DisableMfaResult>,            DisableMfaHandler>();
        services.AddScoped<ICommandHandler<GenerateRecoveryCodesCommand, GenerateRecoveryCodesResult>, GenerateRecoveryCodesHandler>();

        // Tenant handlers
        services.AddScoped<ICommandHandler<CreateTenantCommand,     CreateTenantResult>,     CreateTenantHandler>();
        services.AddScoped<IQueryHandler<GetTenantQuery,            GetTenantResult>,        GetTenantHandler>();
        services.AddScoped<ICommandHandler<UpdateTenantCommand,     UpdateTenantResult>,     UpdateTenantHandler>();
        services.AddScoped<ICommandHandler<DeactivateTenantCommand, DeactivateTenantResult>, DeactivateTenantHandler>();
        services.AddScoped<ICommandHandler<CreateInvitationCommand, CreateInvitationResult>, CreateInvitationHandler>();
        services.AddScoped<ICommandHandler<AcceptInvitationCommand, AcceptInvitationResult>, AcceptInvitationHandler>();

        // Role handlers
        services.AddScoped<ICommandHandler<CreateRoleCommand,   CreateRoleResult>,     CreateRoleHandler>();
        services.AddScoped<ICommandHandler<AssignRoleCommand,   AssignRoleResult>,     AssignRoleHandler>();
        services.AddScoped<ICommandHandler<UnassignRoleCommand, UnassignRoleResult>,   UnassignRoleHandler>();
        services.AddScoped<IQueryHandler<GetPermissionsQuery,   GetPermissionsResult>, GetPermissionsHandler>();
        services.AddScoped<IQueryHandler<ListRolesQuery,        ListRolesResult>,      ListRolesHandler>();

        // Verification handlers
        services.AddScoped<ICommandHandler<VerifyEmailCommand,          VerifyEmailResult>,          VerifyEmailHandler>();
        services.AddScoped<ICommandHandler<RequestPasswordResetCommand, RequestPasswordResetResult>, RequestPasswordResetHandler>();
        services.AddScoped<ICommandHandler<ResetPasswordCommand,        ResetPasswordResult>,        ResetPasswordHandler>();

        // OAuth / OIDC handlers
        services.AddScoped<ICommandHandler<AuthorizeCommand,                  AuthorizeResult>,      AuthorizeHandler>();
        services.AddScoped<ICommandHandler<ExchangeAuthorizationCodeCommand,  TokenExchangeResult>,  ExchangeAuthorizationCodeHandler>();
        services.AddScoped<ICommandHandler<RefreshOAuthTokenCommand,          TokenExchangeResult>,  RefreshOAuthTokenHandler>();
        services.AddScoped<IQueryHandler<GetOidcUserInfoQuery,                GetOidcUserInfoResult>, GetOidcUserInfoHandler>();

        return services;
    }
}
