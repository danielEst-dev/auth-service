using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Auth.Commands;
using AuthService.Application.Features.Auth.Dtos;
using AuthService.Application.Features.Auth.Validators;
using AuthService.Application.Features.Tenants.Dtos;
using AuthService.Application.Features.Tenants.Validators;
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

        // Command handlers — one interface, one implementation per use case
        services.AddScoped<
            ICommandHandler<RegisterUserCommand, RegisterUserResult>,
            RegisterUserHandler>();
        services.AddScoped<
            ICommandHandler<LoginCommand, LoginResult>,
            LoginHandler>();
        services.AddScoped<
            ICommandHandler<CompleteMfaLoginCommand, CompleteMfaLoginResult>,
            CompleteMfaLoginHandler>();

        return services;
    }
}
