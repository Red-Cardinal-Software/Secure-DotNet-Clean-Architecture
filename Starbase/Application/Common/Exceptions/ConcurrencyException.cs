namespace Application.Common.Exceptions;

/// <summary>
/// Exception thrown when a concurrency conflict is detected during a database operation.
/// This occurs when an entity has been modified by another process since it was loaded.
/// </summary>
public class ConcurrencyException : Exception
{
    public ConcurrencyException()
        : base("A concurrency conflict occurred. The record was modified by another process.")
    {
    }

    public ConcurrencyException(string message)
        : base(message)
    {
    }

    public ConcurrencyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}