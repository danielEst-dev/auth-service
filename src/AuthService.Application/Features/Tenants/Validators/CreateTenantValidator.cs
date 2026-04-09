using AuthService.Application.Features.Tenants.Dtos;
using FluentValidation;

namespace AuthService.Application.Features.Tenants.Validators;

public sealed class CreateTenantValidator : AbstractValidator<CreateTenantDto>
{
    private static readonly string[] AllowedPlans = ["free", "pro", "enterprise"];

    public CreateTenantValidator()
    {
        RuleFor(x => x.Slug)
            .NotEmpty()
            .MinimumLength(3)
            .MaximumLength(100)
            .Matches("^[a-z0-9-]+$")
            .WithMessage("Slug may only contain lowercase letters, digits, and hyphens.");

        RuleFor(x => x.Name)
            .NotEmpty()
            .MaximumLength(200);

        RuleFor(x => x.Plan)
            .Must(p => AllowedPlans.Contains(p))
            .WithMessage($"Plan must be one of: {string.Join(", ", AllowedPlans)}.");
    }
}
