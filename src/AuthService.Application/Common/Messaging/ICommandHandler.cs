namespace AuthService.Application.Common.Messaging;

/// <summary>
/// A use-case handler. One command → one handler → one result.
/// Keeps orchestration out of the presentation layer without pulling in MediatR.
/// Inject <c>ICommandHandler&lt;TCommand, TResult&gt;</c> directly at the call site.
/// </summary>
public interface ICommandHandler<in TCommand, TResult>
{
    Task<TResult> HandleAsync(TCommand command, CancellationToken ct = default);
}
