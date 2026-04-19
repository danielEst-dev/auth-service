namespace AuthService.Application.Common.Messaging;

/// <summary>
/// A read-only use case handler. Semantically distinct from <see cref="ICommandHandler{TCommand,TResult}"/>
/// to communicate CQS intent at call sites — queries don't mutate state; commands do.
/// Shape is identical so the DI registration is interchangeable.
/// </summary>
public interface IQueryHandler<in TQuery, TResult>
{
    Task<TResult> HandleAsync(TQuery query, CancellationToken ct = default);
}
