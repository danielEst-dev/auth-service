using AuthService.Application.Features.Auth.Dtos;
using FluentValidation;

namespace AuthService.Application.Features.Auth.Validators;

public sealed class LoginValidator : AbstractValidator<LoginDto>
{
    public LoginValidator()
    {
        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress()
            .MaximumLength(255);

        RuleFor(x => x.Password)
            .NotEmpty()
            .MaximumLength(128);

        RuleFor(x => x.DeviceInfo)
            .MaximumLength(500)
            .When(x => x.DeviceInfo is not null);

        RuleFor(x => x.IpAddress)
            .MaximumLength(45) // IPv6 max
            .When(x => x.IpAddress is not null);
    }
}
