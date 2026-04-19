namespace AuthService.Application.Common.Exceptions;

/// <summary>
/// Thrown when a use case detects a uniqueness / pre-condition conflict (e.g. duplicate email).
/// Presentation adapters translate this into a transport-level "already exists" response.
/// </summary>
public sealed class ConflictException(string message) : Exception(message);
