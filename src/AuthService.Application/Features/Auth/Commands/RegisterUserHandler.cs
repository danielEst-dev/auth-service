using AuthService.Application.Common.Exceptions;
using AuthService.Application.Common.Interfaces;
using AuthService.Application.Common.Messaging;
using AuthService.Application.Features.Auth.Dtos;
using AuthService.Domain.Entities;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace AuthService.Application.Features.Auth.Commands;

public sealed class RegisterUserHandler(
    IUserRepository userRepository,
    IPasswordHasher passwordHasher,
    IDomainEventDispatcher eventDispatcher,
    IValidator<RegisterUserDto> validator,
    ILogger<RegisterUserHandler> logger)
    : ICommandHandler<RegisterUserCommand, RegisterUserResult>
{
    public async Task<RegisterUserResult> HandleAsync(RegisterUserCommand command, CancellationToken ct = default)
    {
        var dto = new RegisterUserDto(command.Email, command.Username, command.Password,
            string.IsNullOrWhiteSpace(command.FirstName) ? null : command.FirstName,
            string.IsNullOrWhiteSpace(command.LastName)  ? null : command.LastName);

        var validation = await validator.ValidateAsync(dto, ct);
        if (!validation.IsValid)
            throw new ValidationException(validation.Errors);

        var normalizedEmail    = command.Email.ToUpperInvariant();
        var normalizedUsername = command.Username.ToUpperInvariant();

        if (await userRepository.ExistsByEmailAsync(command.TenantId, normalizedEmail, ct))
            throw new ConflictException("A user with that email already exists in this tenant.");

        if (await userRepository.ExistsByUsernameAsync(command.TenantId, normalizedUsername, ct))
            throw new ConflictException("A user with that username already exists in this tenant.");

        var user = User.Create(
            tenantId:     command.TenantId,
            email:        command.Email,
            username:     command.Username,
            passwordHash: passwordHasher.Hash(command.Password),
            firstName:    dto.FirstName,
            lastName:     dto.LastName);

        await userRepository.CreateAsync(user, ct);
        await eventDispatcher.DispatchAndClearAsync(user, ct);

        logger.LogInformation("User {UserId} registered in tenant {TenantId}", user.Id, command.TenantId);

        return new RegisterUserResult(user.Id, command.TenantId, user.Email, user.Username);
    }
}
